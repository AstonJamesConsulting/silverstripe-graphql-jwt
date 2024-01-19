<?php

namespace Firesphere\GraphQLJWT\Middleware;

use Exception;
use GraphQL\Type\Schema;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use SilverStripe\GraphQL\Middleware\QueryMiddleware;


class JWTGraphQLMiddleware implements QueryMiddleware
{
  use HeaderExtractor;

  public function process(Schema $schema, string $query, array $context, array $vars, callable $next)
  {

    $auth = Injector::inst()->get(HTTPRequest::class)->getVar('auth_error');

    if ($auth && !$auth->isValid()) {
      foreach ($auth->getMessages() as $code => $error) {
        throw new Exception($error['message']);
      }
    }
    return $next($schema, $query, $context, $vars);
  }
}
