<?php


namespace Firesphere\GraphQLJWT\Resolvers;

use Firesphere\GraphQLJWT\Authentication\CustomAuthenticatorRegistry;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use OutOfBoundsException;
use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Helpers\AnonymousTokenGenerator;
use Firesphere\GraphQLJWT\Helpers\CreateTokenResponseGenerator;
use Firesphere\GraphQLJWT\Helpers\MutationResultGenerator;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use Generator;
use SilverStripe\Core\Config\Configurable;

/**
 * @todo Enum types should allow mapping to these constants (see enums.yml, duplicate code)
 */
class Resolver
{
  use MemberTokenGenerator;
  use AnonymousTokenGenerator;
  use HeaderExtractor;
  use CreateTokenResponseGenerator;
  use MutationResultGenerator;
  use Configurable;

  /**
   * Valid token
   */
  const STATUS_OK = 'OK';

  /**
   * Not a valid token
   */
  const STATUS_INVALID = 'INVALID';

  /**
   * Expired but can be renewed
   */
  const STATUS_EXPIRED = 'EXPIRED';

  /**
   * Expired and cannot be renewed
   */
  const STATUS_DEAD = 'DEAD';

  /**
   * Could not be parsed
   */
  const STATUS_BAD_PARSE = "BAD_PARSE";

  /**
   * JWTRecord does not exist
   */
  const STATUS_DOESNT_EXIST = "DOESNT_EXIST";

  /**
   * Inactivated users cannot login
   */
  const STATUS_INACTIVATED_USER = 'INACTIVE_USER';

  /**
   * Return when a hidden/anonymous mutation result was ok
   */
  const RESULT_OK = 'OK';
  /**
   * Provided user / password were incorrect
   */
  const RESULT_BAD_LOGIN = 'BAD_LOGIN';

  /**
   * Provided user email were incorrect
   */
  const RESULT_BAD_REQUEST = 'BAD_REQUEST';

  /**
   * Provided new password didn't validate
   */
  const RESULT_INVALID_PASSWORD = "INVALID_PASSWORD";

  /**
   * Provided new passwords didn't match
   */
  const RESULT_PASSWORD_MISSMATCH = "PASSWORD_MISSMATCH";

  /**
   * Return when trying to register an account that already exists.
   */
  const RESULT_ALREADY_REGISTERED = "ALREADY_REGISTERED";

  /**
   * Return when trying to reset a password, but the token  was either invalid, expired, already used or changed.
   */
  const RESULT_INVALID_TOKEN = "INVALID_TOKEN";

  /**
   * Return when trying to reset a password, but the token  was either invalid, expired, already used or changed.
   */
  const RESULT_PASSWORD_EXPIRED = "PASSWORD_EXPIRED";

  /**
   * @return mixed
   * @throws \Exception
   */
  public static function resolveValidateToken()
  {
    /** @var JWTAuthenticator $authenticator */
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();
    $token = static::getAuthorizationHeader($request);

    /** @var JWTRecord $record */
    list($record, $status) = $authenticator->validateToken($token, $request);
    $member = $status === self::STATUS_OK ? $record->Member() : null;

    if ($member->isPasswordExpired()) {
      return null;
    }
    
    return static::generateResponse($status, $member, $token);
  }

  /**
   * @return mixed
   * @throws \Exception
   */
  public static function resolveValidateResetToken($object, array $args)
  {
    /** @var JWTAuthenticator $authenticator */
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();
    $token = isset($args['token']) ? $args['token'] : null;

    /** @var JWTRecord $record */
    list(, $status) = $authenticator->validateResetToken($token, $request);
    return static::generateAnonymousResponse($status, $token);
  }

  public static function resolveActivateAccount($object, array $args)
  {
    /** @var JWTAuthenticator $authenticator */
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();
    $token = isset($args['token']) ? $args['token'] : null;

    /** @var JWTRecord $record */
    list($record, $status) = $authenticator->validateSignupToken($token, $request);
    if (!$status === self::STATUS_OK) {
      return static::generateResponse($status, null,  $token);
    }
    $member = Member::get()->filter('SignupTokenID', $record->ID)->first();
    if (!$member) {
      return static::generateResponse(self::STATUS_INVALID, null, $token);
    }

    $member->Activate();

    $memberToken = $authenticator->generateToken($request, $member)->toString();

    return static::generateResponse(self::STATUS_OK, $member, $memberToken);
  }

  public static function resolveCreateAccount($object, array $args)
  {
    $email = isset($args['email']) ? $args['email'] : null;
    $password = isset($args['password']) ? $args['password'] : null;
    $passwordConfirm = isset($args['passwordConfirm']) ? $args['passwordConfirm'] : null;
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();

    if (!$email || !$password || !$passwordConfirm) {
      return static::generateResultResponse(self::RESULT_BAD_REQUEST);
    }

    if ($password !== $passwordConfirm) {
      return static::generateResultResponse(self::RESULT_PASSWORD_MISSMATCH);
    }

    $member = Member::get()->filter('Email', $email)->first();
    if ($member) {
      return static::generateResultResponse(self::RESULT_ALREADY_REGISTERED);
    }

    $member = Member::create();
    $member->Email = $email;
    $result = $member->changePassword($password);
    if (!$result->isValid()) {
      return static::generateResultResponse(self::RESULT_INVALID_PASSWORD, $result->getMessages());
    }
    $member->write();

    $token = $authenticator->generateSignupToken($request, $member);

    // Add mailer class to config to send emails
    $mailerClass = static::config()->get('mailer_class');
    if ($mailerClass) {
      try {
        $mailer = Injector::inst()->get($mailerClass);
        $mailer->sendActivationEmail($member, $token, $request);
      } catch (\Throwable $ex) {
        return static::generateResultResponse(self::RESULT_BAD_REQUEST);
      }
    }

    return static::generateResultResponse(self::RESULT_OK);
  }

  public static function resolveRequestActivationLink($object, array $args)
  {
    $email = isset($args['email']) ? $args['email'] : null;

    if (!$email) {
      return static::generateResultResponse(self::RESULT_BAD_REQUEST);
    }

    $member = Member::get()->filter('Email', $email)->first();
    if (!$member || !$member->requiresActivation()) {
      return static::generateResultResponse(self::RESULT_OK);
    }

    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();

    $token = $authenticator->generateSignupToken($request, $member);

    // Add mailer class to config to send emails
    $mailerClass = static::config()->get('mailer_class');
    if ($mailerClass) {
      try {
        $mailer = Injector::inst()->get($mailerClass);
        $mailer->sendActivationEmail($member, $token, $request);
      } catch (\Throwable $ex) {
        return static::generateResultResponse(self::RESULT_BAD_REQUEST);
      }
    }

    return static::generateResultResponse(self::RESULT_OK);
  }

  /**
   * @return array
   * @throws NotFoundExceptionInterface
   * @throws BadMethodCallException
   * @throws OutOfBoundsException
   * @throws Exception
   */
  public static function resolveRefreshToken($object, array $args): array
  {
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();
    $token = $args['token'];

    // Check status of existing token
    /** @var JWTRecord $record */
    list($record, $status) = $authenticator->validateToken($token, $request);
    $member = null;
    switch ($status) {
      case self::STATUS_OK:
      case self::STATUS_EXPIRED:
        $member = $record->Member();
        $renewable = true;
        break;
      case self::STATUS_DEAD:
      case self::STATUS_INVALID:
      default:
        $member = null;
        $renewable = false;
        break;
    }

    // Check if renewable
    if (!$renewable) {
      return static::generateResponse($status);
    }

    // Create new token for member
    $newToken = $authenticator->generateToken($request, $member);
    return static::generateResponse(self::STATUS_OK, $member, $newToken->toString());
  }


  /**
   * @param mixed $object
   * @param array $args
   * @return array
   * @throws NotFoundExceptionInterface
   */
  public static function resolveCreateToken($object, array $args): array
  {
    // Authenticate this member
    $request = Controller::curr()->getRequest();
    [$member, $validationResult] = static::getAuthenticatedMember($args, $request);

    // Handle unauthenticated
    if (!$member) {
      return static::generateCreateTokenResponse($validationResult);
    }

    if ($member->isPasswordExpired()) {
      return static::generateResponse(self::RESULT_PASSWORD_EXPIRED, null, null);
    }

    // Create new token from this member
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $token = $authenticator->generateToken($request, $member);

    /** @var JWTRecord $record */
    list($record, $status) = $authenticator->validateToken($token->toString(), $request);
    if ($status === self::STATUS_OK) {
      return static::generateResponse($status, $record->Member(), $token->toString());
    }
    return static::generateResponse($status, null, null);
  }

  /**
   * @param mixed $object
   * @param array $args
   * @return array
   * @throws NotFoundExceptionInterface
   */
  public static function resolveRequestResetPassword($object, array $args): array
  {
    // This method should not give any information on wether the email was sent or not
    // only inform if something failed on the server side.

    // Authenticate this member
    $request = Controller::curr()->getRequest();

    $email = isset($args['email']) ? $args['email'] : null;

    if (!$email) {
      return static::generateResultResponse(self::RESULT_BAD_REQUEST);
    }

    $member = Member::get()->filter('Email', $email)->first();
    if (!$member) {
      return static::generateResultResponse(self::RESULT_OK);
    }

    // Create new reset token from this member
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $token = $authenticator->generateResetToken($request, $member);

    // Add mailer class to config to send emails
    $mailerClass = static::config()->get('mailer_class');
    if ($mailerClass) {
      try {
        $mailer = Injector::inst()->get($mailerClass);
        $mailer->sendResetPasswordEmail($member, $token, $request);
      } catch (\Throwable $ex) {
        return static::generateResultResponse(self::RESULT_BAD_REQUEST);
      }
    }

    return static::generateResultResponse(self::RESULT_OK);
  }

  public static function resolveResetPassword($object, array $args)
  {
    $token = isset($args['token']) ? $args['token'] : null;
    $newPassword = isset($args['password']) ? $args['password'] : null;
    $passwordConfirm = isset($args['passwordConfirm']) ? $args['passwordConfirm'] : null;
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();

    if (!$token || !$newPassword || !$passwordConfirm) {
      return static::generateResultResponse(self::RESULT_BAD_REQUEST);
    }

    if ($newPassword !== $passwordConfirm) {
      return static::generateResultResponse(self::RESULT_PASSWORD_MISSMATCH);
    }

    list($record, $status) = $authenticator->validateResetToken($token, $request);

    if ($status !== self::STATUS_OK) {
      return static::generateResultResponse(self::RESULT_INVALID_TOKEN);
    }

    $member = Member::get()->filter('ResetTokenID', $record->ID)->first();

    if (!$member) {
      return static::generateResultResponse(self::RESULT_INVALID_TOKEN);
    }

    $result = $member->changePassword($newPassword);

    if ($result->isValid()) {
      static::afterResetPassword($member);
      return static::generateResultResponse(self::RESULT_OK);
    }

    return static::generateResultResponse(self::RESULT_INVALID_PASSWORD, $result->getMessages());
  }

  protected static function afterResetPassword(Member $member)
  {
    $member->destroyAuthTokens();
    $member->ResetTokenID = null;
    $member->write();
  }


  /**
   * @param mixed $object
   * @param array $args
   * @return array
   * @throws NotFoundExceptionInterface
   */
  public static function resolveLogOut($object, array $args): array
  {
    /** @var JWTAuthenticator $authenticator */
    $authenticator = Injector::inst()->get(JWTAuthenticator::class);
    $request = Controller::curr()->getRequest();
    $token = static::getAuthorizationHeader($request);

    /** @var JWTRecord $record */
    list($record, $status) = $authenticator->validateToken($token, $request);
    $member = $status === self::STATUS_OK ? $record->Member() : null;
    if (!$member) {
      return static::generateResponse($status, $member, $token);
    } else {
      $record->delete();
      return static::generateResponse(self::STATUS_DEAD, $member, $token);
    }
  }

  /**
   * Get any authenticator we should use for logging in users
   *
   * @return Authenticator[]|Generator
   */
  protected static function getLoginAuthenticators(): Generator
  {
    // Check injected authenticators
    yield from CustomAuthenticatorRegistry::singleton()->getCustomAuthenticators();

    // Get other login handlers from Security
    $security = Security::singleton();
    yield from $security->getApplicableAuthenticators(Authenticator::LOGIN);
  }

  /**
   * Get an authenticated member from the given request
   *
   * @param array $args
   * @param HTTPRequest $request
   * @return Member|MemberExtension
   */
  protected static function getAuthenticatedMember(array $args, HTTPRequest $request): array
  {
    // Normalise the casing for the authenticator
    $data = [
      'Email' => $args['email'],
      'Password' => $args['password'] ?? null,
    ];

    // Login with authenticators
    $result = ValidationResult::create();
    foreach (static::getLoginAuthenticators() as $authenticator) {
      $member = $authenticator->authenticate($data, $request, $result);
      if ($member && $result->isValid()) {
        return [$member, null];
      }
    }

    return [null, $result];
  }
}
