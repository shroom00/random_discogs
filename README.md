# Random Discogs

This site allows users to find random releases on Discogs.

Note: there should be a file called `.token` in the repo root, containing your Discogs token. Assuming you do `cargo run -r` from the repo root, an error should be raised if it doesn't exist.

## Config

**bind_address**: The address to bind to (e.g. localhost, 0.0.0.0)

**port**: The port the webserver will listen at (e.g. 80, 443)

**scope**: The base url/scope of the site. If the site is running at the root of the domain, use "/". Otherwise, use "/random_discogs", for example.

## TODO

- Make the site look nice
- Add filtering options for specific genres etc.

![An image of the site](site.jpg)
