// Copyright (c) 2019-2023 Fuego Developers
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2016-2019 The Karbowanec developers
// Copyright (c) 2012-2018 The CryptoNote developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. You can redistribute it and/or modify it under the terms
// of the GNU General Public License v3 or later versions as published
// by the Free Software Foundation. Fuego includes elements written
// by third parties. See file labeled LICENSE for more details.
// You should have received a copy of the GNU General Public License
// along with Fuego. If not, see <https://www.gnu.org/licenses/>.



#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "DaemonCommandsHandler.h"

#include "Common/SignalHandler.h"
#include "Common/PathTools.h"
#include "crypto/hash.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/NetNode.h"
#include "P2p/NetNodeConfig.h"
#include "Rpc/RpcServer.h"
#include "Rpc/RpcServerConfig.h"
#include "version.h"

#include "Logging/ConsoleLogger.h"
#include <Logging/LoggerManager.h>

#if defined(WIN32)
#include <crtdbg.h>
#endif

using Common::JsonValue;
using namespace CryptoNote;
using namespace Logging;

namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string> arg_config_file = {"config-file", "Specify configuration file", std::string(CryptoNote::CRYPTONOTE_NAME) + ".conf"};
  const command_line::arg_descriptor<bool>        arg_os_version  = {"os-version", ""};
  const command_line::arg_descriptor<std::string> arg_log_file    = {"log-file", "", ""};
  const command_line::arg_descriptor<std::string> arg_set_fee_address = { "fee-address", "Set a fee address for remote nodes", "" };
  const command_line::arg_descriptor<std::string> arg_set_view_key = { "view-key", "Set secret view-key for remote node fee confirmation", "" };
  const command_line::arg_descriptor<bool>        arg_restricted_rpc = {"restricted-rpc", "Restrict RPC to view only commands to prevent abuse"};
  const command_line::arg_descriptor<std::string> arg_enable_cors = { "enable-cors", "Adds header 'Access-Control-Allow-Origin' to the daemon's RPC responses. Uses the value as domain. Use * for all", "" };
  const command_line::arg_descriptor<int>         arg_log_level   = {"log-level", "", 2}; // info level
  const command_line::arg_descriptor<bool>        arg_console     = {"no-console", "Disable daemon console commands"};
  const command_line::arg_descriptor<bool>        arg_testnet_on  = {"testnet", "Used to deploy test nets. Checkpoints and hardcoded seeds are ignored, "
    "network id is changed. Use it with --data-dir flag. The wallet must be launched with --testnet flag. "
    "Testnet uses different default ports: P2P=" + std::to_string(P2P_DEFAULT_PORT_TESTNET) + ", RPC=" + std::to_string(RPC_DEFAULT_PORT_TESTNET), false};
  const command_line::arg_descriptor<bool>        arg_print_genesis_tx = { "print-genesis-tx", "Prints genesis' block tx hex to insert it to config and exits" };
}

bool command_line_preprocessor(const boost::program_options::variables_map& vm, LoggerRef& logger);

void print_genesis_tx_hex() {
  Logging::ConsoleLogger logger;
  CryptoNote::Transaction tx = CryptoNote::CurrencyBuilder(logger).generateGenesisTransaction();
  CryptoNote::BinaryArray txb = CryptoNote::toBinaryArray(tx);
  std::string tx_hex = Common::toHex(txb);

  std::cout << "const char GENESIS_COINBASE_TX_HEX[] = \"" << tx_hex << "\";" << std::endl;

  return;
}

JsonValue buildLoggerConfiguration(Level level, const std::string& logfile) {
  JsonValue loggerConfiguration(JsonValue::OBJECT);
  loggerConfiguration.insert("globalLevel", static_cast<int64_t>(level));

  JsonValue& cfgLoggers = loggerConfiguration.insert("loggers", JsonValue::ARRAY);

  JsonValue& fileLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  fileLogger.insert("type", "file");
  fileLogger.insert("filename", logfile);
  fileLogger.insert("level", static_cast<int64_t>(TRACE));

  JsonValue& consoleLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  consoleLogger.insert("type", "console");
  consoleLogger.insert("level", static_cast<int64_t>(TRACE));
  consoleLogger.insert("pattern", "%D %T %L ");

  return loggerConfiguration;
}

void renameDataDir() {
  std::string concealXDir = Tools::getDefaultDataDirectory();
  boost::filesystem::path concealXDirPath(concealXDir);
  if (boost::filesystem::exists(concealXDirPath)) {
    return;
  }

  std::string dataDirPrefix = concealXDir.substr(0, concealXDir.size() + 1 - sizeof(CRYPTONOTE_NAME));
  boost::filesystem::path cediDirPath(dataDirPrefix + "BXC");

  if (boost::filesystem::exists(cediDirPath)) {
    boost::filesystem::rename(cediDirPath, concealXDirPath);
  } else {
    boost::filesystem::path BcediDirPath(dataDirPrefix + "Bcedi");
    if (boost::filesystem::exists(boost::filesystem::path(BcediDirPath))) {
		boost::filesystem::rename(BcediDirPath, concealXDirPath);
    }
  }
}

int main(int argc, char* argv[])
{

#ifdef _WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

  LoggerManager logManager;
  LoggerRef logger(logManager, "daemon");

  try {
    renameDataDir();

    po::options_description desc_cmd_only("Command line options");
    po::options_description desc_cmd_sett("Command line options and settings options");

   desc_cmd_sett.add_options()("enable-blockchain-indexes,i", po::bool_switch()->default_value(false), "Enable blockchain indexes");
   desc_cmd_sett.add_options()("enable-autosave,a", po::bool_switch()->default_value(false), "Enable blockchain autosave every 720 blocks");

   command_line::add_arg(desc_cmd_only, command_line::arg_help);
   command_line::add_arg(desc_cmd_only, command_line::arg_version);
   command_line::add_arg(desc_cmd_only, arg_os_version);
   command_line::add_arg(desc_cmd_only, command_line::arg_data_dir, Tools::getDefaultDataDirectory());
   command_line::add_arg(desc_cmd_only, arg_config_file);
   command_line::add_arg(desc_cmd_sett, arg_restricted_rpc);

   command_line::add_arg(desc_cmd_sett, arg_set_fee_address);
   command_line::add_arg(desc_cmd_sett, arg_log_file);
   command_line::add_arg(desc_cmd_sett, arg_log_level);
   command_line::add_arg(desc_cmd_sett, arg_console);
   command_line::add_arg(desc_cmd_sett, arg_set_view_key);
   command_line::add_arg(desc_cmd_sett, arg_testnet_on);
   command_line::add_arg(desc_cmd_sett, arg_enable_cors);

   command_line::add_arg(desc_cmd_sett, arg_print_genesis_tx);
   //command_line::add_arg(desc_cmd_sett, arg_genesis_block_reward_address);

   RpcServerConfig::initOptions(desc_cmd_sett);
   CoreConfig::initOptions(desc_cmd_sett);
   NetNodeConfig::initOptions(desc_cmd_sett);
   MinerConfig::initOptions(desc_cmd_sett);

   po::options_description desc_options("Allowed options");
   desc_options.add(desc_cmd_only).add(desc_cmd_sett);

   po::variables_map vm;
   bool r = command_line::handle_error_helper(desc_options, [&]() {
     po::store(po::parse_command_line(argc, argv, desc_options), vm);

     if (command_line::get_arg(vm, command_line::arg_help))
     {
       std::cout << "Fuego || " << PROJECT_VERSION_LONG << ENDL;
       std::cout << desc_options << std::endl;
       return false;
     }

     if (command_line::get_arg(vm, arg_print_genesis_tx))
     {
       //print_genesis_tx_hex(vm);
       print_genesis_tx_hex();
       return false;
     }

     std::string data_dir = command_line::get_arg(vm, command_line::arg_data_dir);
     std::string config = command_line::get_arg(vm, arg_config_file);

     boost::filesystem::path data_dir_path(data_dir);
     boost::filesystem::path config_path(config);
     if (!config_path.has_parent_path())
     {
       config_path = data_dir_path / config_path;
     }

     boost::system::error_code ec;
     if (boost::filesystem::exists(config_path, ec))
     {
       po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), desc_cmd_sett), vm);
     }

     po::notify(vm);
     return true;
   });

   if (!r)
   {
     return 1;
    }

    auto modulePath = Common::NativePathToGeneric(argv[0]);
    auto cfgLogFile = Common::NativePathToGeneric(command_line::get_arg(vm, arg_log_file));

    if (cfgLogFile.empty()) {
      cfgLogFile = Common::ReplaceExtenstion(modulePath, ".log");
    } else {
      if (!Common::HasParentPath(cfgLogFile)) {
        cfgLogFile = Common::CombinePath(Common::GetPathDirectory(modulePath), cfgLogFile);
      }
    }

    Level cfgLogLevel = static_cast<Level>(static_cast<int>(Logging::ERROR) + command_line::get_arg(vm, arg_log_level));

    // configure logging
	    logManager.configure(buildLoggerConfiguration(cfgLogLevel, cfgLogFile));
		logger(INFO, BRIGHT_MAGENTA) <<
#ifdef _WIN32
" \n"		
"       8888888888 888     888 8888888888 .d8888b.   .d88888b.   \n" 
"       888        888     888 888       d88P  Y88b d88P` `Y88b  \n"
"       888        888     888 888       888    888 888     888  \n"
"       8888888    888     888 8888888   888        888     888  \n"
"       888        888     888 888       888  88888 888     888  \n"
"       888        888     888 888       888    888 888     888  \n"
"       888        Y88b. .d88P 888       Y88b  d88P Y88b. .d88P  \n"
"       888         `Y88888P`  8888888888 `Y8888P88  `Y88888P`   \n"                                                   
#else
" \n"
" ░░░░░░░ ░░    ░░ ░░░░░░░  ░░░░░░   ░░░░░░  \n"
" ▒▒      ▒▒    ▒▒ ▒▒      ▒▒       ▒▒    ▒▒ \n"
" ▒▒▒▒▒   ▒▒    ▒▒ ▒▒▒▒▒   ▒▒   ▒▒▒ ▒▒    ▒▒ \n"
" ▓▓      ▓▓    ▓▓ ▓▓      ▓▓    ▓▓ ▓▓    ▓▓ \n"
" ██       ██████  ███████  ██████   ██████  \n"
#endif
			"\n"
			<< "             "  PROJECT_VERSION_LONG "\n"
			"\n";

    if (command_line_preprocessor(vm, logger)) {
      return 0;
    }

    logger(INFO) << "Module folder: " << argv[0];

    bool testnet_mode = command_line::get_arg(vm, arg_testnet_on);
    if (testnet_mode) {
      logger(INFO) << "Starting in testnet mode!";
    }

    //create objects and link them
    CryptoNote::CurrencyBuilder currencyBuilder(logManager);
    currencyBuilder.testnet(testnet_mode);

    try {
      currencyBuilder.currency();
    } catch (std::exception&) {
      std::cout << "GENESIS_COINBASE_TX_HEX constant has an incorrect value. Please launch: " << CryptoNote::CRYPTONOTE_NAME << "d --" << arg_print_genesis_tx.name;
      return 1;
    }

    CryptoNote::Currency currency = currencyBuilder.currency();
    CryptoNote::core ccore(currency, nullptr, logManager, vm["enable-blockchain-indexes"].as<bool>(), vm["enable-autosave"].as<bool>());

    CoreConfig coreConfig;
    coreConfig.init(vm);
    NetNodeConfig netNodeConfig;
    netNodeConfig.init(vm);
    netNodeConfig.setTestnet(testnet_mode);
    
    // Set testnet-specific default ports if not explicitly configured
    if (testnet_mode) {
      if (netNodeConfig.getBindPort() == 0) {
        netNodeConfig.setBindPort(P2P_DEFAULT_PORT_TESTNET);
      }
    } else {
      if (netNodeConfig.getBindPort() == 0) {
        netNodeConfig.setBindPort(P2P_DEFAULT_PORT);
      }
    }
    
    MinerConfig minerConfig;
    minerConfig.init(vm);
    RpcServerConfig rpcConfig;
    rpcConfig.init(vm);
    
    // Set testnet-specific RPC port if not explicitly configured
    if (testnet_mode && rpcConfig.bindPort == RPC_DEFAULT_PORT) {
      rpcConfig.bindPort = RPC_DEFAULT_PORT_TESTNET;
    }

    if (!coreConfig.configFolderDefaulted) {
      if (!Tools::directoryExists(coreConfig.configFolder)) {
        throw std::runtime_error("Directory does not exist: " + coreConfig.configFolder);
      }
    } else {
      if (!Tools::create_directories_if_necessary(coreConfig.configFolder)) {
        throw std::runtime_error("Can't create directory: " + coreConfig.configFolder);
      }
    }

    System::Dispatcher dispatcher;

    CryptoNote::CryptoNoteProtocolHandler cprotocol(currency, dispatcher, ccore, nullptr, logManager);
    CryptoNote::NodeServer p2psrv(dispatcher, cprotocol, logManager);
    CryptoNote::RpcServer rpcServer(dispatcher, logManager, ccore, p2psrv, cprotocol);

    cprotocol.set_p2p_endpoint(&p2psrv);
    ccore.set_cryptonote_protocol(&cprotocol);
    DaemonCommandsHandler dch(ccore, p2psrv, logManager, cprotocol);

    // initialize objects
    logger(INFO) << "Initializing p2p server...";
    if (!p2psrv.init(netNodeConfig)) {
      logger(ERROR, BRIGHT_RED) << "Failed to initialize p2p server.";
      return 1;
    }

    logger(INFO) << "P2p server initialized OK";

    // initialize core here
    logger(INFO) << "Initializing core...";
    if (!ccore.init(coreConfig, minerConfig, true)) {
      logger(ERROR, BRIGHT_RED) << "Failed to initialize core";
      return 1;
    }

    logger(INFO) << "Core initialized OK";

    // start components
    if (!command_line::has_arg(vm, arg_console)) {
      dch.start_handling();
    }

    logger(INFO) << "Starting core rpc server on address " << rpcConfig.getBindAddress();
  
    /* Set address for remote node fee */
  	if (command_line::has_arg(vm, arg_set_fee_address)) {
	  std::string addr_str = command_line::get_arg(vm, arg_set_fee_address);
	  if (!addr_str.empty()) {
        AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
        if (!currency.parseAccountAddressString(addr_str, acc)) {
          logger(ERROR, BRIGHT_RED) << "Bad fee address: " << addr_str;
          return 1;
        }
        rpcServer.setFeeAddress(addr_str, acc);
        logger(INFO, BRIGHT_YELLOW) << "Remote node fee address set: " << addr_str;

      }
	  }
  
    /* This sets the view-key so we can confirm that
       the fee is part of the transaction blob */       
    if (command_line::has_arg(vm, arg_set_view_key)) {
      std::string vk_str = command_line::get_arg(vm, arg_set_view_key);
	    if (!vk_str.empty()) {
        rpcServer.setViewKey(vk_str);
        logger(INFO, BRIGHT_YELLOW) << "Secret view key set: " << vk_str;
      }
    }
 
    rpcServer.start(rpcConfig.bindIp, rpcConfig.bindPort);
    rpcServer.restrictRPC(command_line::get_arg(vm, arg_restricted_rpc));
    rpcServer.enableCors(command_line::get_arg(vm, arg_enable_cors));
    logger(INFO) << "Core rpc server started ok";

    Tools::SignalHandler::install([&dch, &p2psrv] {
      dch.stop_handling();
      p2psrv.sendStopSignal();
    });

    logger(INFO) << "Starting p2p net loop...";
    p2psrv.run();
    logger(INFO) << "p2p net loop stopped";

    dch.stop_handling();

    //stop components
    logger(INFO) << "Stopping core rpc server...";
    rpcServer.stop();

    //deinitialize components
    logger(INFO) << "Deinitializing core...";
    ccore.deinit();
    logger(INFO) << "Deinitializing p2p...";
    p2psrv.deinit();

    ccore.set_cryptonote_protocol(NULL);
    cprotocol.set_p2p_endpoint(NULL);

  } catch (const std::exception& e) {
    logger(ERROR, BRIGHT_RED) << "Exception: " << e.what();
    return 1;
  }

  logger(INFO) << "Node stopped.";
  return 0;
}

bool command_line_preprocessor(const boost::program_options::variables_map &vm, LoggerRef &logger) {
  bool exit = false;

  if (command_line::get_arg(vm, command_line::arg_version)) {
    std::cout << CryptoNote::CRYPTONOTE_NAME << PROJECT_VERSION_LONG << ENDL;
    exit = true;
  }

  if (command_line::get_arg(vm, arg_os_version)) {
    std::cout << "OS: " << Tools::get_os_version_string() << ENDL;
    exit = true;
  }

  if (exit) {
    return true;
  }

  return false;
}
