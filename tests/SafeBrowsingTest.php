<?php

use Ampersa\SafeBrowsing\SafeBrowsing;

class SafeBrowsingTest extends PHPUnit_Framework_TestCase
{
    protected $apiKey = 'AIzaSyApJRWzpYwsQaFM3_PQakTL4Y3kUBwDis0';

    public function testDirtyDomainReturnsTrue()
    {
        $safebrowsing = new SafeBrowsing($this->apiKey);
        $result = $safebrowsing->listed('http://ianfette.org/');

        $this->assertTrue($result);
    }

    public function testCleanDomainReturnsFalse()
    {
        $safebrowsing = new SafeBrowsing($this->apiKey);
        $result = $safebrowsing->listed('http://google.com');

        $this->assertFalse($result);
    }

    public function testConfigSets()
    {
        $safebrowsing = new SafeBrowsing($this->apiKey, ['threatTypes' => ['MALWARE']]);
        $result = $safebrowsing->listed('http://google.com');

        $this->assertFalse($result);
    }

    public function testReturnThreatType()
    {
        $safebrowsing = new SafeBrowsing($this->apiKey);
        $result = $safebrowsing->listed('http://ianfette.org/', true);

        $this->assertEquals('MALWARE', $result);
    }

    public function testEmptyApiKeyException()
    {
        $this->expectException(Exception::class);
        $safebrowsing = new SafeBrowsing('');
        $result = $safebrowsing->listed('http://google.com');
    }

    public function testBadApiKeyException()
    {
        $this->expectException(GuzzleHttp\Exception\ClientException::class);
        $safebrowsing = new SafeBrowsing('A BAD API KEY');
        $result = $safebrowsing->listed('http://google.com');
    }
}
