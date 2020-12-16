try {
  // parse the json object from cache value
  var prodcache = JSON.parse(context.getVariable("prodcache"));

  // set variables for response
  context.setVariable("productlist", prodcache.productlist);
  context.setVariable("response.header.etag", prodcache.etag);
} catch (e) {
  throw 'Error in parse-product-cache javascript execution';
}