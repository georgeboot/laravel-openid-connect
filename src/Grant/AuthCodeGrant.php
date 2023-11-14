<?php

namespace OpenIDConnect\Grant;

use Illuminate\Support\Arr;
use League\OAuth2\Server\Grant\AuthCodeGrant as BaseAuthCodeGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use Nyholm\Psr7\Response as Psr7Response;

class AuthCodeGrant extends BaseAuthCodeGrant
{
    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        /** @var RedirectResponse $response */
        $response = parent::completeAuthorizationRequest($authorizationRequest);

        if (request()->query->has('nonce')) {
            $httpResponse = $response->generateHttpResponse(new Psr7Response());

            $redirectUri = Arr::first($httpResponse->getHeader('Location'));

            $parsed = parse_url($redirectUri);

            parse_str($parsed['query'], $query);

            $authCodePayload = json_decode($this->decrypt($query['code']), true);

            $authCodePayload['nonce'] = request()->query('nonce');

            $query['code'] = $this->encrypt(json_encode($authCodePayload));

            $parsed['query'] = http_build_query($query);

            $response->setRedirectUri($this->unparse_url($parsed));
        }

        return $response;
    }

    /**
     * Inverse of parse_url
     *
     * @param mixed $parsed_url
     * @return string
     */
    private function unparse_url($parsed_url)
    {
        $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
        $host     = isset($parsed_url['host']) ? $parsed_url['host'] : '';
        $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
        $user     = isset($parsed_url['user']) ? $parsed_url['user'] : '';
        $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass'] : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = isset($parsed_url['path']) ? $parsed_url['path'] : '';
        $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
        $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
        return "$scheme$user$pass$host$port$path$query$fragment";
    }
}
