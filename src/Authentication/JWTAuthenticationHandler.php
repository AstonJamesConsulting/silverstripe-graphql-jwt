<?php

declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Authentication;

use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use OutOfBoundsException;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\SessionManager\Models\LoginSession;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\SessionManager\Security\LogInAuthenticationHandler;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\ORM\ValidationException;
use SilverStripe\GraphQL\QueryHandler\QueryException;


/**
 * Class JWTAuthenticationHandler
 *
 * @package Firesphere\GraphQLJWT
 */
class JWTAuthenticationHandler implements AuthenticationHandler
{
    use HeaderExtractor;
    use Injectable;

    /**
     * @param HTTPRequest $request
     * @return null|Member
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     * @throws Exception
     */
    public function authenticateRequest(HTTPRequest $request)
    {
        // Check token
        $token = $this->getAuthorizationHeader($request);
        if (!$token) {
            return null;
        }

        $result = ValidationResult::create();

        // Validate the token. This is critical for security
        $member = Injector::inst()->get(JWTAuthenticator::class)->authenticate(['token' => $token], $request, $result);
        $request['auth_error'] = $result;

        if (!$member) return false;

        if ($member->ID && $result->isValid()) {
            return $member;
        }
    }

    /**
     * Authenticate on every run, based on the header, not relying on sessions or cookies
     * JSON Web Tokens are stateless
     *
     * @param Member $member
     * @param bool $persistent
     * @param HTTPRequest|null $request
     */
    public function logIn(Member $member, $persistent = false, HTTPRequest $request = null): void
    {
        Security::setCurrentUser($member);
    }

    /**
     * @param HTTPRequest|null $request
     */
    public function logOut(HTTPRequest $request = null): void
    {
        // A token can actually not be invalidated, but let's flush all valid tokens from the DB.
        // Note that log-out acts as a global logout (all devices)
        /** @var Member|MemberExtension $member */
        $member = Security::getCurrentUser();
        if ($member) {
            $member->destroyAuthTokens();
        }
        Security::setCurrentUser(null);
    }
}
