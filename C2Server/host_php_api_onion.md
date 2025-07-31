# Host Your PHP API on a .onion Address with Tor

## Step 1: Install and Configure Tor

```bash
sudo apt update
sudo apt install tor -y
```

Edit the Tor configuration:

```bash
sudo nano /etc/tor/torrc
```

Add at the end:

```
HiddenServiceDir /var/lib/tor/myapi_hidden_service/
HiddenServicePort 80 127.0.0.1:8000
```

## Step 2: Get Your .onion Address

Restart Tor:

```bash
sudo systemctl restart tor
```

Get your .onion domain:

```bash
sudo cat /var/lib/tor/myapi_hidden_service/hostname
```

This is your `.onion` address.

## Step 3: Run Your PHP API Locally

```bash
php -S localhost:8000
```

Your API is now running on `127.0.0.1:8000`.

## Step 4: Access the .onion Address

Use the [Tor Browser](https://www.torproject.org/) to access your `.onion` domain.

Just enter the address you got earlier, and...

✅ You’ll see the result of your `.php` API endpoints.
