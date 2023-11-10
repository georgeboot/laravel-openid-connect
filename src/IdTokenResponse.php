<?php

namespace OpenIDConnect;

use DateInterval;
use DateTimeImmutable;
use Illuminate\Support\Facades\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use OpenIDConnect\Interfaces\IdentityEntityInterface;
use OpenIDConnect\Interfaces\IdentityRepositoryInterface;

class IdTokenResponse extends BearerTokenResponse
{
    protected IdentityRepositoryInterface $identityRepository;

    protected ClaimExtractor $claimExtractor;

    private Configuration $config;

    private array $tokenHeaders;

    private bool $useMicroseconds;

    public function __construct(
        IdentityRepositoryInterface $identityRepository,
        ClaimExtractor $claimExtractor,
        Configuration $config,
        array $tokenHeaders = [],
        bool $useMicroseconds = true
    ) {
        $this->identityRepository = $identityRepository;
        $this->claimExtractor = $claimExtractor;
        $this->config = $config;
        $this->tokenHeaders = $tokenHeaders;
        $this->useMicroseconds = $useMicroseconds;
    }

    protected function getBuilder(
        AccessTokenEntityInterface $accessToken,
        IdentityEntityInterface $userEntity
    ): Builder {
        $dateTimeImmutableObject = DateTimeImmutable::createFromFormat(
            ($this->useMicroseconds ? 'U.u' : 'U'),
            ($this->useMicroseconds ? microtime(true) : time())
        );

        return $this->config
            ->builder()
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy('https://' . Request::host())
            ->issuedAt($dateTimeImmutableObject)
            ->expiresAt($dateTimeImmutableObject->add(new DateInterval('PT1H')))
            ->relatedTo($userEntity->getIdentifier());
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if (!$this->hasOpenIDScope(...$accessToken->getScopes())) {
            return [];
        }

        $user = $this->identityRepository->getByIdentifier(
            (string) $accessToken->getUserIdentifier(),
        );

        $builder = $this->getBuilder($accessToken, $user);

        foreach ($this->tokenHeaders as $key => $value) {
            $builder = $builder->withHeader($key, $value);
        }

        $claims = $this->claimExtractor->extract(
            $accessToken->getScopes(),
            $user->getClaims(),
        );

        foreach ($claims as $claimName => $claimValue) {
            $builder = $builder->withClaim($claimName, $claimValue);
        }

        $token = $builder->getToken(
            $this->config->signer(),
            $this->config->signingKey(),
        );

        return ['id_token' => $token->toString()];
    }

    private function hasOpenIDScope(ScopeEntityInterface ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                return true;
            }
        }
        return false;
    }
}
