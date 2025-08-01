// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/base.h>
#include <openssl/pem.h>
#include "internal.h"
#include "../tool/internal.h"

static const argument_t kArguments[] = {
        { "-help", kBooleanArgument, "Display option summary" },
        { "-connect", kRequiredArgument,
                "The hostname and port of the server to connect to, e.g. foo.com:443" },
        { "-CAfile", kOptionalArgument,
                "A file containing trusted certificates to use during server authentication "
                "and to use when attempting to build the client certificate chain. " },
        { "-CApath", kOptionalArgument,
                "The directory to use for server certificate verification. " },
        { "-showcerts", kBooleanArgument,
                "Displays the server certificate list as sent by the server: it only "
                "consists of certificates the server has sent (in the order the server "
                "has sent them). It is not a verified chain. " },
        { "-verify", kOptionalArgument,
                "The verify depth to use. This specifies the maximum length of the server "
                "certificate chain and turns on server certificate verification. "
                "Currently the verify operation continues after errors so all the problems "
                "with a certificate chain can be seen. As a side effect the connection will "
                "never fail due to a server certificate verify failure." },
        { "", kOptionalArgument, "" },
};

bool SClientTool(const args_list_t &args) {
  using namespace ordered_args;
  ordered_args_map_t parsed_args;
  args_list_t extra_args;

  if (!ParseOrderedKeyValueArguments(parsed_args, extra_args, args, kArguments) ||
      extra_args.size() > 0) {
    PrintUsage(kArguments);
    return false;
  }

  if(HasArgument(parsed_args, "-help")) {
    fprintf(stderr, "Usage: s_client [options] [host:port]\n");
    PrintUsage(kArguments);
    return true;
  }

  // Convert to std::map for DoClient compatibility
  std::map<std::string, std::string> args_map;
  for (const auto &arg_pair : parsed_args) {
    args_map[arg_pair.first] = arg_pair.second;
  }

  return DoClient(args_map, true);
}
