<?php

namespace OpenIDConnect\Laravel;

use Illuminate\Encryption\Encrypter;
use Laravel\Passport;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\ClientRepository;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use League\OAuth2\Server\AuthorizationServer;
use OpenIDConnect\ClaimExtractor;
use OpenIDConnect\Claims\ClaimSet;
use OpenIDConnect\Grant\AuthCodeGrant;
use OpenIDConnect\IdTokenResponse;
use Laravel\Passport\Bridge;

class PassportServiceProvider extends Passport\PassportServiceProvider
{
    public function register()
    {
        parent::register();

        $this->mergeConfigFrom(
            __DIR__ . '/config/openid.php',
            'openid'
        );
    }

    public function boot()
    {
        parent::boot();

        $this->publishes([
            __DIR__ . '/config/openid.php' => $this->app->configPath('openid.php'),
        ], ['openid', 'openid-config']);
    }

    public function makeAuthorizationServer(): AuthorizationServer
    {
        $cryptKey = $this->makeCryptKey('private');

        $customClaimSets = config('openid.custom_claim_sets');

        $claimSets = array_map(function ($claimSet, $name) {
            return new ClaimSet($name, $claimSet);
        }, $customClaimSets, array_keys($customClaimSets));

        $responseType = new IdTokenResponse(
            app(config('openid.repositories.identity')),
            new ClaimExtractor(...$claimSets),
            Configuration::forSymmetricSigner(
                app(config('openid.signer')),
                InMemory::plainText($cryptKey->getKeyContents(), $cryptKey->getPassPhrase() ?? '')
            ),
            config('openid.token_headers'),
            config('openid.use_microseconds')
        );

        return new AuthorizationServer(
            app(ClientRepository::class),
            app(AccessTokenRepository::class),
            app(Passport\Bridge\ScopeRepository::class),
            $cryptKey,
            app(Encrypter::class)->getKey(),
            $responseType,
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function buildAuthCodeGrant()
    {
        return new AuthCodeGrant(
            $this->app->make(Bridge\AuthCodeRepository::class),
            $this->app->make(Bridge\RefreshTokenRepository::class),
            new \DateInterval('PT10M')
        );
    }
}
