This package enables you to query Google's SafeBrowsing service to determine if a URL exists in their database.

## Installation
Composer
```
$ composer require ampersa/safebrowsing
```

## Usage
Use of the Google SafeBrowsing API (v4) requires a valid API key. Details can be found at https://developers.google.com/safe-browsing/v4/get-started

**Basic usage**  
```php
use Ampersa\SafeBrowsing\SafeBrowsing;
...

$safebrowsing = new SafeBrowsing(API_KEY);
$result = $safebrowsing->listed('http://ianfette.org');
// Returns: (bool) true
```

The listed() function accepts a second boolen argument, which when `true` returns the threat type as reported by SafeBrowsing
```php
$safebrowsing = new SafeBrowsing(API_KEY);
$result = $safebrowsing->listed('http://ianfette.org', true);
// Returns: (string) MALWARE
```

## Testing
To run the unit tests within this package, you will need to edit the tests/SafeBrowsingTest.php file and enter a functional SafeBrowsing API key

## Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request
