// Copyright (c) 2017-2024 Fuego Developers
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2014-2018 The Monero project
// Copyright (c) 2018-2019 The Ryo Currency developers
// Copyright (c) 2014-2018 The Forknote developers
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

#include <cstdint>
#include <initializer_list>
#include <boost/uuid/uuid.hpp>

namespace CryptoNote
{
	namespace parameters
	{
		const uint64_t DIFFICULTY_TARGET = 480;	
		const uint64_t CRYPTONOTE_MAX_BLOCK_NUMBER = 500000000;
		const size_t CRYPTONOTE_MAX_BLOCK_BLOB_SIZE = 500000000;
		const size_t CRYPTONOTE_MAX_TX_SIZE = 1000000000;
                const uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 1753191; /* "fire" address prefix */
		const size_t CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 60;	
		const uint64_t DIFFICULTY_TARGET_DRGL = 81;
		const unsigned EMISSION_SPEED_FACTOR = 18;
                const unsigned EMISSION_SPEED_FACTOR_FANGO = 19;  //major version 8
                const unsigned EMISSION_SPEED_FACTOR_FUEGO = 20;   //major version 9
		const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT  = 60 * 60 * 2;
		const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1 = DIFFICULTY_TARGET_DRGL * 6;
		const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2 = DIFFICULTY_TARGET * 2;
		const uint64_t CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10;
		const size_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 60;
		const size_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1 = 11; /* LWMA3 */

		const uint64_t MONEY_SUPPLY = UINT64_C(80000088000008); /* max supply: 8M8 */
		const uint64_t COIN = UINT64_C(10000000);			  
		const uint64_t MINIMUM_FEE_V1 = UINT64_C(800000);
		const uint64_t MINIMUM_FEE_V2 = UINT64_C(80000);	/* 0.008 XFG */
		const uint64_t MINIMUM_FEE = MINIMUM_FEE_V2;		
		const uint64_t MINIMUM_FEE_BANKING = UINT64_C(80000);  /* 0.008 XFG */
		const uint64_t DEFAULT_DUST_THRESHOLD = UINT64_C(20000); /* < 0.002 XFG */
		const size_t   MINIMUM_MIXIN = 2;

		const size_t   CRYPTONOTE_COIN_VERSION                       = 1;
		const size_t   CRYPTONOTE_DISPLAY_DECIMAL_POINT 	     = 7;
		const size_t   CRYPTONOTE_REWARD_BLOCKS_WINDOW               = 100;
		const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE     = 800000; //size of block (bytes) after reward for block is calculated in block-size
		const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2  = 800000;
		const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1  = 20000;
		const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_CURRENT = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
		const size_t   CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE        = 600;

		const uint64_t EXPECTED_NUMBER_OF_BLOCKS_PER_DAY             = 24 * 60 * 60 / DIFFICULTY_TARGET;
		const size_t   DIFFICULTY_CUT                                = 60;  // v0
		const size_t   DIFFICULTY_LAG                                = 15;  // v0
		const size_t   DIFFICULTY_WINDOW                             = 1067; // blocks  Original CryptoNote
		const size_t   DIFFICULTY_WINDOW_V2                          = 18;  // blocks  Zawy v1.0
		const size_t   DIFFICULTY_WINDOW_V3                          = 60;  // blocks  Zawy-LWMA1
		const size_t   DIFFICULTY_WINDOW_V4                          = 45;  // blocks  Zawy-LWMA1 Fuego (~180 block per day)

		const uint64_t MIN_TX_MIXIN_SIZE                             = 2;
               // const uint64_t MIN_TX_MIXIN_SIZE_V9                          = 8;
		const uint64_t MAX_TX_MIXIN_SIZE                             = 18;
		static_assert(2 * DIFFICULTY_CUT <= DIFFICULTY_WINDOW - 2, "Bad DIFFICULTY_WINDOW or DIFFICULTY_CUT");

		const uint64_t DEPOSIT_MIN_AMOUNT = 800 * COIN;
		const uint32_t DEPOSIT_MIN_TERM_v1 = 5480;  //blocks
                const uint32_t DEPOSIT_MAX_TERM_v1 = 5480; 
                const uint32_t DEPOSIT_MIN_TERM = 16440;  //blocks		 /* one month=5480 ( 3 months (16440) for release ) OverviewFrame::depositParamsChanged */
                const uint32_t DEPOSIT_MAX_TERM = 16440;  		 /* 3 month standard */

		static_assert(DEPOSIT_MIN_TERM > 0, "Bad DEPOSIT_MIN_TERM");
		static_assert(DEPOSIT_MIN_TERM <= DEPOSIT_MAX_TERM, "Bad DEPOSIT_MAX_TERM");
		const uint64_t MULTIPLIER_FACTOR = 100;		 /* legacy deposits */
		const uint32_t END_MULTIPLIER_BLOCK = 50; /* legacy deposits */

		static constexpr uint64_t POISSON_CHECK_TRIGGER = 10; // Reorg size that triggers poisson timestamp check
		static constexpr uint64_t POISSON_CHECK_DEPTH = 60;   // Main-chain depth of poisson check. The attacker will have to tamper 50% of those blocks
		static constexpr double POISSON_LOG_P_REJECT = -75.0; // Reject reorg if probability of timestamps being genuine is less than e^x, -75 = 10^-33

		const size_t   MAX_BLOCK_SIZE_INITIAL                        = 800000;  
		const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR         = 100 * 1024;
		const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR       = 365 * 24 * 60 * 60 / DIFFICULTY_TARGET;

		const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS     = 1;
		const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS    = DIFFICULTY_TARGET_DRGL * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;
		const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 = DIFFICULTY_TARGET * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;		   

		const size_t CRYPTONOTE_MAX_TX_SIZE_LIMIT = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_CURRENT - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE; /* maximum transaction size */
		const size_t CRYPTONOTE_OPTIMIZE_SIZE=  100;		/* proportional to CRYPTONOTE_MAX_TX_SIZE_LIMIT */

		const uint64_t CRYPTONOTE_MEMPOOL_TX_LIVETIME = (60 * 60 * 12);					/* 1 hour in seconds */
		const uint64_t CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = (60 * 60 * 12);	/* 24 hours in seconds */
		const uint64_t CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL = 7; /* CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL * CRYPTONOTE_MEMPOOL_TX_LIVETIME  = time to forget tx */

		const size_t FUSION_TX_MAX_SIZE = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 30 / 100;
		const size_t FUSION_TX_MIN_INPUT_COUNT = 12;
		const size_t FUSION_TX_MIN_IN_OUT_COUNT_RATIO = 4;

		const uint32_t UPGRADE_HEIGHT_V2                             = 147958; //{Hardhome}
 		const uint32_t UPGRADE_HEIGHT_V3                             = 154321; //{Longclaw}
 		const uint32_t UPGRADE_HEIGHT_V4                             = 300000; //{Dracarys}
 		const uint32_t UPGRADE_HEIGHT_V5                             = 324819; //{Ironborn}  CN7  (variant1) 
 		const uint32_t UPGRADE_HEIGHT_V6                             = 345678; //{Ice&fire}  CN8  (variant2)
                const uint32_t UPGRADE_HEIGHT_V7                             = 657000; //Apotheosis  Fango
		const uint32_t UPGRADE_HEIGHT_V8                             = 800000; //Dragonborne (emission|deposits)
                const uint32_t UPGRADE_HEIGHT_V9                             = 826420; //Godflame  (emission|UPX2|Fuego)
		const unsigned UPGRADE_VOTING_THRESHOLD = 90; // percent
		const size_t UPGRADE_VOTING_WINDOW = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
		const size_t UPGRADE_WINDOW = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;

		static_assert(0 < UPGRADE_VOTING_THRESHOLD && UPGRADE_VOTING_THRESHOLD <= 100, "Bad UPGRADE_VOTING_THRESHOLD");
		static_assert(UPGRADE_VOTING_WINDOW > 1, "Bad UPGRADE_VOTING_WINDOW");

		const char CRYPTONOTE_BLOCKS_FILENAME[] = "blocks.dat";
 		const char CRYPTONOTE_BLOCKINDEXES_FILENAME[] = "blockindexes.dat";
 		const char CRYPTONOTE_BLOCKSCACHE_FILENAME[] = "blockscache.dat";
 		const char CRYPTONOTE_POOLDATA_FILENAME[] = "poolstate.bin";
 		const char P2P_NET_DATA_FILENAME[] = "p2pstate.bin";
 		const char CRYPTONOTE_BLOCKCHAIN_INDICES_FILENAME[] = "blockchainindices.dat";
 		const char MINER_CONFIG_FILE_NAME[] = "miner_conf.json";

	} // namespace parameters

        const char CRYPTONOTE_NAME[] = "fuego";
	const char GENESIS_COINBASE_TX_HEX[] = "013c01ff0001b4bcc29101029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd0880712101bd4e0bf284c04d004fd016a21405046e8267ef81328cabf3017c4c24b273b25a";
	
	// Testnet Genesis Block
	const char GENESIS_COINBASE_TX_HEX_TESTNET[] = "013c01ff0001b4bcc29101029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd0880712101bd4e0bf284c04d004fd016a21405046e8267ef81328cabf3017c4c24b273b25a";

	const uint8_t  TRANSACTION_VERSION_1                         =  1;
	const uint8_t  TRANSACTION_VERSION_2                         =  2;
	const uint8_t  BLOCK_MAJOR_VERSION_1                         =  1;
	const uint8_t  BLOCK_MAJOR_VERSION_2                         =  2;
	const uint8_t  BLOCK_MAJOR_VERSION_3                         =  3;
	const uint8_t  BLOCK_MAJOR_VERSION_4                         =  4;
	const uint8_t  BLOCK_MAJOR_VERSION_5                         =  5;
	const uint8_t  BLOCK_MAJOR_VERSION_6                         =  6;
	const uint8_t  BLOCK_MAJOR_VERSION_7                         =  7;
	const uint8_t  BLOCK_MAJOR_VERSION_8                         =  8; 
	const uint8_t  BLOCK_MAJOR_VERSION_9                         =  9;
	const uint8_t  BLOCK_MINOR_VERSION_0 			     =  0;
	const uint8_t  BLOCK_MINOR_VERSION_1 			     =  1;

	const size_t BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT = 10000; // by default, blocks ids count in synchronizing
	const size_t BLOCKS_SYNCHRONIZING_DEFAULT_COUNT = 128;		 // by default, blocks count in blocks downloading
	const size_t COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT = 1000;

	const int P2P_DEFAULT_PORT = 10808;
 	const int RPC_DEFAULT_PORT = 18180;

	// Testnet Configuration
	const int P2P_DEFAULT_PORT_TESTNET = 20808;
	const int RPC_DEFAULT_PORT_TESTNET = 28180;
	const uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_TESTNET = 1753192; /* "test" address prefix */
	
	// Network IDs - Different network IDs prevent mainnet/testnet cross-communication
	const boost::uuids::uuid CRYPTONOTE_NETWORK = { { 0x46, 0x55, 0x45, 0x47, 0x4f, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x20, 0x20 } }; // "FUEGO NETWORK   "
	const boost::uuids::uuid CRYPTONOTE_NETWORK_TESTNET = { { 0x54, 0x45, 0x53, 0x54, 0x20, 0x46, 0x55, 0x45, 0x47, 0x4f, 0x20, 0x4e, 0x45, 0x54, 0x20, 0x20 } }; // "TEST FUEGO NET  "

	/* P2P Network Configuration Section - This defines our current P2P network version
	and the minimum version for communication between nodes */
	const uint8_t P2P_VERSION_1 = 1;
	const uint8_t P2P_VERSION_2 = 2;
	const uint8_t P2P_CURRENT_VERSION = 1;
	const uint8_t P2P_MINIMUM_VERSION = 1;
	const uint8_t P2P_UPGRADE_WINDOW = 2;

	// This defines the minimum P2P version required for lite blocks propogation
	const uint8_t P2P_LITE_BLOCKS_PROPOGATION_VERSION = 3;

	const size_t P2P_LOCAL_WHITE_PEERLIST_LIMIT = 1000;
	const size_t P2P_LOCAL_GRAY_PEERLIST_LIMIT = 5000;

	const size_t P2P_CONNECTION_MAX_WRITE_BUFFER_SIZE = 64 * 1024 * 1024; // 64MB
	const uint32_t P2P_DEFAULT_CONNECTIONS_COUNT = 8;
	const size_t P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT = 2;
	const size_t P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT = 70; // percent
	const uint32_t P2P_DEFAULT_HANDSHAKE_INTERVAL = 60;			 // seconds
	const uint32_t P2P_DEFAULT_PACKET_MAX_SIZE = 50000000;		 // 50000000 bytes maximum packet size
	const uint32_t P2P_DEFAULT_PEERS_IN_HANDSHAKE = 250;
	const uint32_t P2P_DEFAULT_CONNECTION_TIMEOUT = 5000;	   // 5 seconds
	const uint32_t P2P_DEFAULT_PING_CONNECTION_TIMEOUT = 2000; // 2 seconds
	const uint64_t P2P_DEFAULT_INVOKE_TIMEOUT = 60 * 2 * 1000; // 2 minutes
	const size_t P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT = 5000;  // 5 seconds
        const uint32_t P2P_IP_BLOCKTIME         = (60 * 60 * 24);  // 24 hr
        const uint32_t P2P_IP_FAILS_BEFORE_BLOCK  =  45;
	const char P2P_STAT_TRUSTED_PUB_KEY[] = "";

	// Seed Nodes
	const std::initializer_list<const char *> SEED_NODES = {
		"3.16.217.33:10808",
 		"80.89.228.157:10808",
 		"207.244.247.64:10808",
	        "216.145.66.224:10808"
			
	};
	
	// Testnet Seed Nodes
	const std::initializer_list<const char *> SEED_NODES_TESTNET = {
		"127.0.0.1:20808",  // Local testnet node - replace with actual testnet seed nodes
		// Add more testnet seed nodes here as they become available
	};

	struct CheckpointData
	{
		uint32_t height;
		const char *blockId;
	};

#ifdef __GNUC__
	__attribute__((unused))
#endif
	// Blockchain Checkpoints:
	// {<block height>, "<block hash>"},
	const std::initializer_list<CheckpointData>
		CHECKPOINTS = {
 			{ 800,    "c1c64f752f6f5f6f69671b3794f741af0707c71b35302ea4fc96b0befdce8ce9" },
 			{ 8008,   "299702f163995cd790b5c45362c78ad596f8717d749ff9016ce27eaa625b8a5e" },
 			{ 18008,  "46baf8aea2b9472a9f127ad7cdcb01a871ecf20d710e9e0d3a2b13176a452112" },
 			{ 63312,  "57c815dd1480b6a1de7037f85aa510ff7c784b91808f3777451c030d40614ddb" },
 			{ 80008,  "19e65aec81a283e756c9b55a884927bcbffa4639c9fe21fd4894ef211e0e8472" },
 			{ 108801, "0cb48287678f9df42a63c6c344f448ddce5316f9c5c03548e77d9a1193ebf5fd" },
 			{ 147959, "cecc0692782cd1956fb12bf170c4ebd6c7b6bb5c12e7071ef2d98e7c940f1961" },
 			{ 148000, "bd318f33b5f1804bc648ce847d4214cff8cfd7498483461db660a87e342eb0e9" },
 			{ 154322, "73232b04d18cdc9cc6430194298166c6e775a55ff0f48e2f819f8ed5fd873df7" },
 			{ 155433, "89be8af3d0a62454e95cf71cf7c17df9480ac337b4b5a294e0d75400b8989700" },
 			{ 158000, "153b22f4912d1a6db9f235de40ae2be3a178eb44cbde8e2a4fe0c7727037ab34" },
 			{ 180018, "3c0c6fd2f6c2805280f2079f50f772433957fae495ad81e305835bdb935fd21e" },
 			{ 200000, "4c4555f73e54b43f62fe26950d3c7f877e35c448a1e865b5ea07aa09d971e0e5" },
 			{ 222222, "801d187ca11851d0379c0fa4a790d26aa24e76835d26bf7e54f4b858bfd7ad53" },
 			{ 250000, "1a2cfc1c53a62038468feff7f22a150a95ba65090842d09fadd97f789e1e00fc" },
 			{ 260000, "968fc54cd727b5d70c4ccc1f9fe144c58bd909acc97cd27c491c4f6fc1b97087" },
 			{ 280000, "fa6016236d07c8a5ab660f5ddd788f2f002bd518146e2bc379dd66d1bc7f94a8" },
 			{ 300001, "ba7e401c03a9f5b2111ef402d8715761990ff53e31069c413f5c78c7cd819de9" },
 			{ 320000, "2c42f527960ce443ffa645b0af85d85bdf10cf9df8625d900b4edd0b29b68735" },
 			{ 324820, "99fb6b6c81c9ceff7bcdef0667cf270a5300dec6393de21bd599d414eef38569" },
 			{ 333333, "d58919713e37e4317a3e50c12639fe591958d2e43637cf8f99f596c6c8275241" },
 			{ 342600, "cae28d470dddbc42fbc0f0a9d3345add566f23dea8130c9ae900697d0e1580c9" },
 			{ 345679, "8ce385e3816ce48adfe13952e010d1207eaf006e366e67c65f0e19cd1a550ce1" },
 			{ 369369, "e32cf1e1b365690fb95544ce35c0e2c0ea846fab12cbd5c70a1d336689325973" },
 			{ 400004, "07b68b28622969c3df1987d0d5c6259cedf661f277039662e817051384c9b5af" },
 			{ 444444, "b3dd057a72e415861db116f9f7e49c3e9417e29614bf4962fe4f90e4632d0cef" },
 			{ 500000, "30138ff16e9925fe7a8d2db702cf52da2822c614066c3d41d6bcbb704a47eeeb" },
 			{ 555555, "b8bca0bc95a995f60e6e70d3d6d5efde291c4eb7a7ce4a76b126b47354ce74ef" },
 			{ 600000, "bea84c3cde5c6c47ea739e33e09e39b672c33acae434d34ccc5bf1d8177fe29c" },
 			{ 620000, "aff4cbc82e142ef03e4e4a9953034071c21752f9a7c00e5b385aa0cac0eeb9bb" },
 			{ 640000, "63f664a39a9bc958fa61e5088862ab117f1f513fda16584f4ec7031087661fce" },
 			{ 656000, "35b04e2217494c7b818eccad9b7f7fadc3d8d23a8e216dfcff444691fd57fc0f" },
 			{ 656114, "6c5ff7712c1bd5716679969b3903a6711b258202e78a729907c2af0eb299214c" },
 			{ 657001, "68cc01388e1e4a1b4a8fc885e911f0c09dbea594183111047d926fad41669a09" },
 			{ 657002, "29952d93e156602008c03070089d6ba6375e770dda5d31603d7493eec23e8618" },
 			{ 657025, "b654644cc363120a88f15e044cbe04935f7a0e347a72901a46d1db88348a7392" },
 			{ 690000, "294f9c92ec345d23543ce7dfb7d2487cb6d3b3c64e6d0158b165bf9f530aef30" },
 			{ 696969, "da78f75378ca0d84108f636119cb228ba7185f953f36511c4c80812d77664050" },
 			{ 700000, "1ffc42a47c84a82a2a050d1607bbd5a4524c3b47099f6cf61f8dab5b24abbf2a" },
 			{ 710000, "c7493d9721e3d5ebd196f035d8bb74bd5485443181840b05f62dd0b7709a14c4" },
 			{ 720000, "673574f7b28a84ef81fb00f072d378fca271ba48e77250f225748c35ce873619" },
 			{ 730000, "25020873d7851cd0b0787d8dd6a5eb758eb5c531bc793837e9399d9f05e0a4a4" },
 			{ 740000, "5c1b20e346df61f719a6d39cef03ca53d6978f4b00915b61ce139a67a5ea5d8d" },
 			{ 750000, "4fe3b7759428705b39f725ef1f5a9ce1b501c983de5e3079d30bc497f587242f" },
 			{ 752411, "8675187b8a7bdf73ac93ac9d86f37315c0780a41ff4c0aa671f5d809b6c5b631" },
 			{ 752593, "e270b1419d5ae8589ea8fdb148a6de6b02637432e76a1b23258324754a16f46f" },
			{ 777777, "82cbbe5436b1f273b4b7b3ebe6517cfe4ddff33dd365e438cc44f456f43fa71b" },
		        { 800001, "ee744efcc80fe4a483b21bf6918f72bfa19ca2b4324b51786c522428acffce98" },
 	         	{ 810000, "ca66bed2600a0750f4dafe8ec7a8e4581b2ab9df326cc8f321ffd96bc2947b2c" },
	        	{ 820000, "6bb848f23668412e35c7bdcd60cd0aea70761d11f1f41204a1b8ca2d808e79d7" },
			{ 826421, "9a0158c87c062c63a675c65eda91c10bb6d7b68b854be783aa85b2cbbf3b8a55" },
			{ 830000, "cee38b0701df9f26a938f6c65a1f233d1f810e5f19eb1b4cb87b15d514342064" },
			{ 840000, "ec767b0e56d7002966e3184e197b3da06c5f94484bf6218781a38f59a75bfaab" },
			{ 888888, "b818f74d11ab6b16f86455986b3078217dd2eb0cac3de9b9a0c3111ebb07b9dc" },
			{ 895000, "2bc71e117bf0544ec1c4a193a0c012c106f0bedc0c27b62feeef944bb16b83e3" }





 		};

} // namespace CryptoNote

#define ALLOW_DEBUG_COMMANDS
//Knowledge has made you powerful but there is still so much you don't know.
