// Minimal Mongoose web server for Nerva fingerprinter integration testing.
// Serves directory listing on port 8000 with default Mongoose configuration.

#include "mongoose.h"

static void fn(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct mg_http_serve_opts opts = {.root_dir = "/data"};
    mg_http_serve_dir(c, hm, &opts);
  }
}

int main(void) {
  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, "http://0.0.0.0:8000", fn, NULL);
  for (;;) mg_mgr_poll(&mgr, 1000);
  return 0;
}
