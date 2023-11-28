<?php

namespace Firesphere\GraphQLJWT\Middleware;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use SilverStripe\SessionManager\Middleware\LoginSessionMiddleware;

class JWTLoginSessionMiddleware extends LoginSessionMiddleware
{
  use HeaderExtractor;

  /**
   * @param HTTPRequest $request
   * @param callable $delegate
   * @return HTTPResponse
   */
  public function process(HTTPRequest $request, callable $delegate)
  {
    
    $token = $this->getAuthorizationHeader($request);
    if ($token) {
        return $delegate($request);
    }

    return parent::process($request, $delegate);
  }
}
