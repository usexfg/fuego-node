// Copyright (c) 2017-2025 Fuego Developers
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

#pragma once

#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <chrono>
#include <boost/program_options/variables_map.hpp>

#include "IWalletLegacy.h"
#include "PasswordContainer.h"

#include "Common/ConsoleHandler.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/Currency.h"
#include "NodeRpcProxy/NodeRpcProxy.h"
#include "WalletLegacy/WalletHelper.h"

#include <Logging/LoggerRef.h>
#include <Logging/LoggerManager.h>

#include <System/Dispatcher.h>
#include <System/Ipv4Address.h>

std::string remote_fee_address;
namespace CryptoNote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class simple_wallet : public CryptoNote::INodeObserver, public CryptoNote::IWalletLegacyObserver, public CryptoNote::INodeRpcProxyObserver {
  public:
    simple_wallet(System::Dispatcher& dispatcher, const CryptoNote::Currency& currency, Logging::LoggerManager& log);

    bool init(const boost::program_options::variables_map& vm);
    bool deinit();
    bool run();
    void stop();

    bool process_command(const std::vector<std::string> &args);
    std::string get_commands_str();
    std::string getFeeAddress();

    const CryptoNote::Currency& currency() const { return m_currency; }

  private:

    Logging::LoggerMessage success_msg_writer(bool color = false) {
      return logger(Logging::INFO, color ? Logging::GREEN : Logging::DEFAULT);
    }

    Logging::LoggerMessage fail_msg_writer() const {
      auto msg = logger(Logging::ERROR, Logging::BRIGHT_RED);
      msg << "Error: ";
      return msg;
    }

    void handle_command_line(const boost::program_options::variables_map& vm);

    bool run_console_handler();

    bool new_wallet(const std::string &wallet_file, const std::string& password);
    bool new_wallet(Crypto::SecretKey &secret_key, Crypto::SecretKey &view_key, const std::string &wallet_file, const std::string& password);
    bool open_wallet(const std::string &wallet_file, const std::string& password);
    bool close_wallet();

    bool help(const std::vector<std::string> &args = std::vector<std::string>());
    bool exit(const std::vector<std::string> &args);
    bool start_mining(const std::vector<std::string> &args);
    bool show_dust(const std::vector<std::string> &args);
    bool stop_mining(const std::vector<std::string> &args);
    bool show_balance(const std::vector<std::string> &args = std::vector<std::string>());
    bool sign_message(const std::vector<std::string> &args);
    bool verify_signature(const std::vector<std::string> &args);
    bool export_keys(const std::vector<std::string> &args = std::vector<std::string>());
    bool create_integrated(const std::vector<std::string> &args = std::vector<std::string>());
    bool show_incoming_transfers(const std::vector<std::string> &args);
    bool show_payments(const std::vector<std::string> &args);
    bool show_blockchain_height(const std::vector<std::string> &args);
    bool show_num_unlocked_outputs(const std::vector<std::string> &args);
    bool optimize_outputs(const std::vector<std::string> &args);
	  bool get_reserve_proof(const std::vector<std::string> &args);    
    bool get_tx_proof(const std::vector<std::string> &args);    
    bool optimize_all_outputs(const std::vector<std::string> &args);
    bool listTransfers(const std::vector<std::string> &args);
    bool transfer(const std::vector<std::string> &args);
    bool print_address(const std::vector<std::string> &args = std::vector<std::string>());
    bool save(const std::vector<std::string> &args);
    bool reset(const std::vector<std::string> &args);
    bool set_log(const std::vector<std::string> &args);
    bool payment_id(const std::vector<std::string> &args);

    bool ask_wallet_create_if_needed();
    std::string resolveAlias(const std::string& aliasUrl);
    void printConnectionError() const;

    std::string generate_mnemonic(Crypto::SecretKey &);
    void log_incorrect_words(std::vector<std::string>);
    bool is_valid_mnemonic(std::string &, Crypto::SecretKey &);


    //---------------- IWalletLegacyObserver -------------------------
    virtual void initCompleted(std::error_code result) override;
    virtual void externalTransactionCreated(CryptoNote::TransactionId transactionId) override;
    virtual void synchronizationCompleted(std::error_code result) override;
    virtual void synchronizationProgressUpdated(uint32_t current, uint32_t total) override;
    //----------------------------------------------------------

    //----------------- INodeRpcProxyObserver --------------------------
    virtual void connectionStatusUpdated(bool connected) override;
    //----------------------------------------------------------

    friend class refresh_progress_reporter_t;

    class refresh_progress_reporter_t
    {
    public:
      refresh_progress_reporter_t(CryptoNote::simple_wallet& simple_wallet)
        : m_simple_wallet(simple_wallet)
        , m_blockchain_height(0)
        , m_blockchain_height_update_time()
        , m_print_time()
      {
      }

      void update(uint64_t height, bool force = false)
      {
        auto current_time = std::chrono::system_clock::now();
        if (std::chrono::seconds(m_simple_wallet.currency().difficultyTarget() / 2) < current_time - m_blockchain_height_update_time ||
            m_blockchain_height <= height) {
          update_blockchain_height();
          m_blockchain_height = (std::max)(m_blockchain_height, height);
        }

        if (std::chrono::milliseconds(1) < current_time - m_print_time || force) {
          std::cout << "Height " << height << " of " << m_blockchain_height << '\r';
          m_print_time = current_time;
        }
      }

    private:
      void update_blockchain_height()
      {
        uint64_t blockchain_height = m_simple_wallet.m_node->getLastLocalBlockHeight();
        m_blockchain_height = blockchain_height;
        m_blockchain_height_update_time = std::chrono::system_clock::now();
      }

    private:
      CryptoNote::simple_wallet& m_simple_wallet;
      uint64_t m_blockchain_height;
      std::chrono::system_clock::time_point m_blockchain_height_update_time;
      std::chrono::system_clock::time_point m_print_time;
    };

  private:
    std::string m_wallet_file_arg;
    std::string m_generate_new;
    std::string m_import_new;
    std::string m_import_path;

    std::string m_daemon_address;
    std::string m_daemon_host;
    uint16_t m_daemon_port;

    std::string m_wallet_file;

    std::unique_ptr<std::promise<std::error_code>> m_initResultPromise;

    Common::ConsoleHandler m_consoleHandler;
    const CryptoNote::Currency& m_currency;
    Logging::LoggerManager& logManager;
    System::Dispatcher& m_dispatcher;
    Logging::LoggerRef logger;

    std::unique_ptr<CryptoNote::NodeRpcProxy> m_node;
    std::unique_ptr<CryptoNote::IWalletLegacy> m_wallet;
    refresh_progress_reporter_t m_refresh_progress_reporter;

    bool m_walletSynchronized;
    std::mutex m_walletSynchronizedMutex;
    std::condition_variable m_walletSynchronizedCV;
  };
}
