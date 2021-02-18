try {
  //generate a hash with the productlist
  var sha512 = crypto.getSHA512();
  sha512.update(response.content);

  //convert to base64
  prodcache = {
      "etag": sha512.digest(),
      "productlist": response.content
  }

  // set headers
  context.setVariable("prodcache", JSON.stringify(prodcache));
  context.setVariable("response.header.etag", prodcache.etag);

} catch(e) {
  throw 'Error in set-product-cache javascript execution';
}