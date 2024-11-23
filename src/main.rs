pub(crate) mod config;
pub(crate) mod constants;

use std::{
    collections::HashMap,
    fmt::Debug,
    fs::{self, File},
    hash::{DefaultHasher, Hash, Hasher},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use actix_files::Files;
use actix_web::{
    get,
    rt::time::sleep,
    web::{scope, Data},
    App, HttpResponse, HttpServer, Responder,
};
use constants::{CONFIG, TOKEN};
use rand::{distributions::WeightedError, seq::SliceRandom, thread_rng, Rng};
use reqwest::{
    header::{self, HeaderMap},
    Client, IntoUrl, StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use tera::{Context, Tera};
use tl::{parse_owned, NodeHandle, Parser, ParserOptions, VDomGuard};

macro_rules! timeit {
    ($name:literal = $($token:tt)+) => {
        {
            let now = std::time::Instant::now();
            let out = {$($token)+};
            println!("{} took {:.3?}", $name, now.elapsed());
            out
        }
    };
}

const BASE_URL: &'static str = "www.discogs.com";
const BASE_API_URL: &'static str = "api.discogs.com";
const MAX_RESULTS: u32 = 10_000;
const WEIGHTED: bool = true;

#[derive(Debug, Serialize)]
struct ApiResult {
    title: String,
    labels: Vec<(String, Option<String>)>,
    formats: Vec<String>,
    country: String,
    genres: Vec<String>,
    styles: Vec<String>,
    year: String,
    cover: Option<String>,
    uri: String,
}

async fn make_api_request(client: &Client, url: String) -> ApiResult {
    println!("making api request to {url}");
    let response = loop {
        let response = client.get(&url).send().await.unwrap();
        if response
            .headers()
            .get("x-discogs-ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap()
            != "0"
        {
            break response;
        } else {
            sleep(Duration::from_secs(2)).await
        }
    };

    let text = response.text().await.unwrap();
    let result = &serde_json::from_str::<Value>(&text).unwrap()["results"][0];

    let title = result["title"]
        .as_str()
        .and_then(|title| {
            Some(
                title
                    .chars()
                    .rev()
                    .collect::<String>()
                    .replacen(" - ", " – ", 1)
                    .chars()
                    .rev()
                    .collect::<String>(),
            )
        })
        .unwrap_or(String::new());
    let labels = result["labels"]
        .as_array()
        .and_then(|labels| {
            Some(
                labels
                    .into_iter()
                    .map(|label| {
                        (
                            label["name"].as_str().unwrap().to_string(),
                            label["catno"].as_str().map(|catno| catno.to_string()),
                        )
                    })
                    .collect::<Vec<(String, Option<String>)>>(),
            )
        })
        .or({
            result["label"].as_array().and_then(|label| {
                Some(vec![(
                    label[0].as_str().unwrap().to_string(),
                    result["catno"].as_str().map(|catno| catno.to_string()),
                )])
            })
        })
        .unwrap_or(vec![]);
    let formats = result["format"]
        .as_array()
        .and_then(|formats| {
            Some(
                formats
                    .into_iter()
                    .map(|format| format.as_str().unwrap().to_string())
                    .collect::<Vec<String>>(),
            )
        })
        .unwrap_or(vec![]);
    let country = result["country"].as_str().unwrap_or("?").to_string();
    let genres = result["genre"]
        .as_array()
        .unwrap_or(&vec![])
        .into_iter()
        .map(|genre| genre.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let styles = result["style"]
        .as_array()
        .unwrap_or(&vec![])
        .into_iter()
        .map(|style| style.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let year = result["year"].as_str().unwrap_or("?").to_string();
    let cover = {
        let cover = result["thumb"].as_str().unwrap();
        if cover == "" {
            None
        } else {
            Some(cover.to_string())
        }
    };
    let uri = format!(
        "https://{BASE_URL}{}",
        result["uri"].as_str().unwrap().to_string()
    );

    // Label: label - catno
    // Format: format, format[description][0], format[description][0], ...
    // Country: country
    // Release Year: year
    // Genre: genre[0], genre[1], ...
    // Style: style[0], style[1], ...

    ApiResult {
        title,
        labels,
        formats,
        country,
        genres,
        styles,
        year,
        cover,
        uri,
    }
}

async fn get_html<U: IntoUrl + Debug>(client: &Client, url: U) -> Result<VDomGuard, StatusCode> {
    let request = client.get(url);
    let response = request.send().await.unwrap();
    if !response.status().is_success() {
        Err(response.status())
    } else {
        match response.text().await {
            Ok(text) => unsafe {
                Ok(
                    parse_owned(text, ParserOptions::default().track_ids().track_classes())
                        .unwrap(),
                )
            },
            Err(_) => unimplemented!(),
        }
    }
}

fn pop_random<T>(v: &mut Vec<T>) -> T {
    v.remove(thread_rng().gen_range(0..(v.len())))
}

#[derive(Debug, PartialEq)]
enum Filters {
    Genre,
    Style,
    Format,
    Country,
    Decade,
    Year,
}

impl Filters {
    fn selector(&self) -> &str {
        match self {
            Filters::Genre => "#facets_genre_exact",
            Filters::Style => "#facets_style_exact",
            Filters::Format => "#facets_format_exact",
            Filters::Country => "#facets_country_exact",
            Filters::Decade => "#facets_decade",
            Filters::Year => ".facets_nav:last-of-type",
        }
    }

    fn extract_info(element: NodeHandle, parser: &Parser) -> Option<(String, String, u32)> {
        let url_suffix = element
            .get(parser)
            .and_then(|node| {
                let find_href = |node: &tl::Node| {
                    if let Some(tag) = node.as_tag() {
                        tag.name().try_as_utf8_str().unwrap() == "a"
                    } else {
                        false
                    }
                };

                if find_href(node) {
                    Some(node)
                } else {
                    node.children()
                        .unwrap()
                        .all(parser)
                        .into_iter()
                        .find(|child| find_href(child))
                }
            })
            .and_then(|node| {
                node.as_tag()
                    .unwrap()
                    .attributes()
                    .get("href")
                    .flatten()
                    .and_then(|bytes| bytes.try_as_utf8_str())
            })
            .unwrap_or("");

        let name = element
            .get(parser)
            .and_then(|node| {
                node.as_tag()
                    .unwrap()
                    .query_selector(parser, ".facet_name")
                    .and_then(|mut matches| {
                        matches.next().and_then(|node| {
                            Some(node.get(parser).unwrap().inner_text(parser).to_string())
                        })
                    })
            })
            .unwrap_or_default();

        let count = element
            .get(parser)
            .and_then(|node| {
                node.as_tag()
                    .unwrap()
                    .query_selector(parser, ".facet_count")
                    .and_then(|mut matches| {
                        matches.next().and_then(|node| {
                            node.get(parser)
                                .unwrap()
                                .inner_text(parser)
                                .to_string()
                                .replace(",", "")
                                .parse::<u32>()
                                .ok()
                        })
                    })
            })
            .unwrap_or(0);

        if (count != 0) & (url_suffix != "") & (name != "") {
            Some((
                format!("https://{BASE_URL}{url_suffix}"),
                name.to_string(),
                count,
            ))
        } else {
            None
        }
    }

    /// Returns (url, name, count)
    fn _get_choices(&self, html: &VDomGuard) -> Vec<(String, String, u32)> {
        let filter_selector = self.selector();
        let vdom = html.get_ref();
        let parser = vdom.parser();
        let choices = vdom
            .query_selector(filter_selector)
            .and_then(|mut selector_matches| {
                selector_matches.next().and_then(|filter_list_handle| {
                    filter_list_handle.get(parser).and_then(|filter_list| {
                        filter_list.as_tag().and_then(|filter_list_tag| {
                            Some(
                                filter_list_tag
                                    .query_selector(parser, "li")
                                    .unwrap()
                                    .filter_map(|list_item| Self::extract_info(list_item, parser))
                                    .collect::<Vec<_>>(),
                            )
                        })
                    })
                })
            })
            .unwrap_or(vec![]);
        if choices.is_empty() {
            // If there are only a few choices, the popup with every choice won't exist.
            // Instead, the choices are stored in the sidebar.
            vdom.query_selector("#page_aside")
                .unwrap()
                .next()
                .unwrap()
                .get(parser)
                .and_then(|aside| {
                    aside
                        .as_tag()
                        .and_then(|aside_tag| aside_tag.query_selector(parser, "a"))
                })
                .unwrap()
                .filter_map(|list_item_link| {
                    let href = list_item_link
                        .get(parser)
                        .unwrap()
                        .as_tag()
                        .unwrap()
                        .attributes()
                        .get("href")
                        .flatten()
                        .unwrap()
                        .try_as_utf8_str()
                        .unwrap();
                    if href.split('&').last().unwrap().starts_with(self.keyword()) {
                        Self::extract_info(list_item_link, parser)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            choices
        }
    }

    /// Returns Err(None) if `choices` is empty
    fn choose(
        mut choices: Vec<(String, String, u32)>,
        weighted_override: Option<bool>,
    ) -> Option<(String, String, u32)> {
        if choices.is_empty() {
            None
        } else {
            let weighted = weighted_override.unwrap_or(WEIGHTED);
            Some(if weighted {
                loop {
                    if choices.is_empty() {
                        return None;
                    }
                    match choices
                        .choose_weighted(&mut thread_rng(), |(_, _, count)| *count)
                        .cloned()
                    {
                        Ok(result) => break result,
                        Err(e) => match e {
                            WeightedError::InvalidWeight | WeightedError::TooMany => {
                                pop_random(&mut choices);
                                continue;
                            }
                            _ => unimplemented!(),
                        },
                    }
                }
            } else {
                choices.choose(&mut thread_rng()).unwrap().clone()
            })
        }
    }

    async fn select<U: IntoUrl + Debug + Hash + Copy>(
        &self,
        client: &Client,
        url: U,
        weighted_override: Option<bool>,
        cache: &ResponseCache,
    ) -> Result<(String, String, u32), StatusCode> {
        loop {
            let choices = if *self == Self::Year {
                let choices = timeit!(
                    "getting response " =
                        cache.get_response(&client, url, &Filters::Decade).await?
                );
                let decade_url = Self::choose(choices, weighted_override).unwrap().0;
                timeit!("getting response " = cache.get_response(&client, decade_url, &self).await?)
            } else {
                timeit!("getting response " = cache.get_response(&client, url, &self).await?)
            };
            break Ok(Self::choose(choices, weighted_override).unwrap());
        }
    }

    fn keyword(&self) -> &str {
        match self {
            Filters::Genre => "genre",
            Filters::Style => "style",
            Filters::Format => "format",
            Filters::Country => "country",
            Filters::Decade => "decade",
            Filters::Year => "year",
        }
    }
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, header::HeaderValue::from_static(BASE_URL));
    headers.insert(
        header::ACCEPT,
        header::HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
    );
    headers.insert(header::DNT, header::HeaderValue::from_static("1"));
    headers.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("keep-alive"),
    );
    headers.insert(
        header::UPGRADE_INSECURE_REQUESTS,
        header::HeaderValue::from_static("1"),
    );
    headers
}

fn make_client() -> Client {
    Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        )
        .default_headers(headers())
        .cookie_store(true)
        .use_rustls_tls()
        .build()
        .unwrap()
}

#[get("/")]
async fn get_random(cache: Data<ResponseCache>, tera: Data<Tera>) -> impl Responder {
    println!("-------------------------------");
    let mut count = 1;
    let client = make_client();
    loop {
        match get_api_params(&client, cache.as_ref()).await {
            Ok((mut params, count)) => {
                params
                    .iter_mut()
                    .for_each(|(_, v)| *v = urlencoding::encode(&v).to_string());
                let random_page = thread_rng().gen_range(0..=count);

                let api_query_params = params
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<String>>()
                    .join("&");
                let api_url = format!("https://{BASE_API_URL}/database/search?{api_query_params}&page={random_page}&type=release&per_page=1&token={}", TOKEN.as_str());

                let api_result = make_api_request(&client, api_url).await;

                let context = Context::from_serialize(api_result).unwrap();

                // Render the template using Tera
                break match tera.render("index.tera", &context) {
                    Ok(rendered) => HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .body(rendered),
                    Err(e) => HttpResponse::InternalServerError()
                        .body(format!("Error rendering template: {e}")),
                };
            }
            Err(status) => {
                if (count == 3) | (status != StatusCode::FORBIDDEN) {
                    break HttpResponse::build(actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap()).body(format!("Received {status} from Discogs, sorry! If this persists, raise an issue on the github repo."));
                }
                println!("trying again after 403");
                count += 1;
            }
        }
    }
}

async fn get_api_params(
    client: &Client,
    cache: &ResponseCache,
) -> Result<(HashMap<String, String>, u32), StatusCode> {
    let mut filters = vec![
        Filters::Genre,
        Filters::Format,
        Filters::Year,
        Filters::Country,
        Filters::Style,
    ];

    debug_assert!(
        !filters.contains(&Filters::Decade),
        "Decade only exists as it's needed to get the year, it shouldn't be in the filter list"
    );

    let mut search_url = format!("https://{BASE_URL}/search/?type=release&limit=25&layout=sm");

    let mut api_params = HashMap::<String, String>::new();
    let mut count = 0;
    loop {
        let filter = match filters.is_empty() {
            true => {
                break;
            }
            false => filters.pop().unwrap(),
        };

        let (url, name, new_count) = filter.select(&client, &search_url, None, cache).await?;
        count = new_count;
        api_params.insert(filter.keyword().to_string(), name);
        search_url = url;
        if count <= MAX_RESULTS {
            break;
        }
    }

    Ok((api_params, count.min(MAX_RESULTS)))
}

struct ResponseCache {
    expiry_seconds: u64,
    directory: PathBuf,
}

impl ResponseCache {
    fn new<D: Into<PathBuf>>(expiry_seconds: u64, directory: D) -> Self {
        let directory = directory.into();
        fs::create_dir_all(&directory).unwrap();
        Self {
            expiry_seconds,
            directory,
        }
    }

    async fn get_response<U: IntoUrl + Debug + Hash>(
        &self,
        client: &Client,
        url: U,
        filter: &Filters,
    ) -> Result<Vec<(String, String, u32)>, StatusCode> {
        println!("sending get to {url:?}");

        let mut query_params = url
            .as_str()
            .split_once('?')
            .unwrap()
            .1
            .split('&')
            .collect::<Vec<_>>();
        query_params.sort();

        let query_hash = {
            let mut hasher = DefaultHasher::new();
            query_params.hash(&mut hasher);
            hasher.finish()
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check for an existing cache file
        if let Some(cached_file) = self.get_single_cache_file(query_hash) {
            println!("{url:?} is cached at {cached_file:?}");
            if let Some(timestamp) = self.get_timestamp_from_filename(&cached_file) {
                if now - timestamp < self.expiry_seconds {
                    // Read cached data
                    let data: Vec<(String, String, u32)> =
                        serde_json::from_reader(File::open(&cached_file).unwrap()).unwrap();
                    return Ok(data);
                } else {
                    fs::remove_file(cached_file).unwrap(); // Remove expired file
                }
            }
        }

        // Fetch data if no valid cache
        let out = get_html(client, url).await;
        match out {
            Ok(ref vdom) => {
                let choices = filter._get_choices(vdom);

                // Delete any existing files for this query hash
                self.delete_all_cache_files(query_hash);

                // Save new cache file with timestamp in the filename
                let fp = self.directory.join(format!("{query_hash}_{now}.json"));
                serde_json::to_writer(File::create(&fp).unwrap(), &choices).unwrap();

                Ok(choices)
            }
            Err(status) => Err(status),
        }
    }

    fn get_single_cache_file(&self, query_hash: u64) -> Option<PathBuf> {
        fs::read_dir(&self.directory)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with(&format!("{query_hash}_")))
                    .unwrap_or(false)
            })
    }

    fn delete_all_cache_files(&self, query_hash: u64) {
        for cached_file in self.get_cache_files(query_hash) {
            fs::remove_file(cached_file).unwrap();
        }
    }

    fn get_cache_files(&self, query_hash: u64) -> Vec<PathBuf> {
        fs::read_dir(&self.directory)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with(&format!("{query_hash}_")))
                    .unwrap_or(false)
            })
            .collect()
    }

    fn get_timestamp_from_filename(&self, path: &Path) -> Option<u64> {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split('_').nth(1))
            .and_then(|timestamp| timestamp.strip_suffix(".json"))
            .and_then(|timestamp| timestamp.parse().ok())
    }
}
#[actix_web::main]
pub async fn main() -> Result<(), std::io::Error> {
    let config_scope = CONFIG.scope.trim_end_matches('/').to_string();
    let server = match HttpServer::new({
        let config_scope = config_scope.clone();
        move || {
            let mut tera = Tera::new("./templates/*").unwrap();
            tera.autoescape_on(vec![".html", ".htm", ".xml", ".tera"]);
            let cache = ResponseCache::new(60 * 60 * 24 * 2, "cache");
            if config_scope.len() == 0 {
                App::new()
            } else {
                App::new().service(scope(&config_scope))
            }
            .app_data(Data::new(cache))
            .app_data(Data::new(tera))
            .service(get_random)
            .service(Files::new("/css", "./css"))
            .service(Files::new("/static", "./static"))
        }
    })
    .bind((CONFIG.bind_address.as_str(), CONFIG.port))
    {
        Ok(server) => server,
        Err(e) => return Result::Err(e),
    };

    let addrs = server.addrs_with_scheme();
    println!("Site running at:");
    addrs
        .into_iter()
        .for_each(|(addr, scheme)| println!("\t{scheme}://{addr}{}", config_scope));

    let server = server.run();
    server.await
}
