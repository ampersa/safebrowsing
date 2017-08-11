<?php

namespace Ampersa\SafeBrowsing;

use Exception;
use GuzzleHttp\Client as HttpClient;

class SafeBrowsing
{
    /** @var string */
    protected $apiKey;

    /** @var array */
    protected $config = [
        'threatTypes' => [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        'platformTypes' => [
            'ANY_PLATFORM',
        ],
    ];

    public function __construct(string $apiKey, array $config = [])
    {
        $this->apiKey = $apiKey;
        $this->config = array_merge($this->config, $config);
    }

    /**
     * Return listed status from Google Safebrowsing. Returns true on listed status
     * @param  string $url
     * @param  bool   $returnType
     * @return bool|string
     */
    public function listed(string $url, $returnType = false)
    {
        if (empty($this->apiKey)) {
            throw new Exception('A Google Safebrowsing has not been specified');
        }

        // Retrieve the result from SafeBrowsing
        $result = $this->getSafebrowsingResult($url);

        // Check for exististance of the supplied URL in any matches
        if (is_object($result) and isset($result->matches)) {
            foreach ($result->matches as $match) {
                if ($match->threat->url == $url) {
                    // Return the Threat Type if requested,
                    // otherwise return true
                    if ($returnType) {
                        return $match->threatType;
                    }
                    
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Prepare the request to Google Safebrowsing, retrieve the result
     * and decode before returning.
     * @param  string $url
     * @return object
     */
    protected function getSafebrowsingResult(string $url)
    {
        // Prepare the Safebrowsing API URL and
        // populate the API key for the request
        $safebrowsingUrl = sprintf('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s', $this->apiKey);

        // Prepare the payload that will be sent
        // to Google Safebrowsing API as JSON
        $safebrowsingPayload = [
            'client' => [
                'clientId' => 'Ampersa/SafeBrowsing',
                'clientVersion' => '0.1',
            ],
            'threatInfo' => [
                'threatTypes' => [
                    'MALWARE',
                    'SOCIAL_ENGINEERING',
                    'UNWANTED_SOFTWARE',
                    'POTENTIALLY_HARMFUL_APPLICATION',
                ],
                'platformTypes' => [
                    'ANY_PLATFORM'
                ],
                'threatEntryTypes' => [
                    'URL',
                ],
                'threatEntries' => [
                    [
                        'url' => $url
                    ],
                ],
            ]
        ];

        // Prepare the request and get the response
        try {
            $response = (new HttpClient)->post($safebrowsingUrl, [
                'json' => $safebrowsingPayload
            ]);
        } catch (Exception $e) {
            return json_decode([]);
        }

        // Retrieve and decode the result from the response
        $result = json_decode((string) $response->getBody());

        return $result;
    }
}
