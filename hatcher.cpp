#include <vector>
#include <ctype.h>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/asset.hpp>
#include <eosiolib/action.hpp>
#include <eosiolib/symbol.hpp>
#include <eosiolib/crypto.h>
#include <eosiolib/transaction.hpp>

#define CORE_TOKEN symbol("EOS", 4)         // EOS
#define CORE_ACCOUNT name("eosio.token")    // eosio.token

#define ISSUE_TOKEN symbol("EEGG", 4)         // 发行代币EEGG
#define ISSUE_ACCOUNT name("eegg.bank")   // 发行代币账户eegg.bank

#define TEAM_ACCOUNT name("warehouse.e")    // 团队利润账号 = 总利润
#define DEVE_ACCOUNT name("eosiodrizzle")    // 研发利润账号 = 总利润 - 3500EOS * 10%
#define CONF_ACCOUNT name("buyname.io")    // 系统配置账户 buyname.io
#define DRAW_ACCOUNT name("eeggcpu.e")    // 订单结算账户 
#define LOGS_ACCOUNT name("eegglog.e")    // 系统日志账户 


using namespace std;
using namespace eosio;

CONTRACT stardustcore : public contract {


  private:

    const string REMARK = "--- 鹅蛋是全球首个EOS短账号挖矿平台，官网：http://eegg.io。";

    bool is_digits(const std::string &str){
        return std::all_of(str.begin(), str.end(), ::isdigit); 
    }

    size_t string_split(const string& input,string* output,const char& separator,const size_t& first_pos = 0,const bool& required = false) {
        eosio_assert(first_pos != string::npos, "解析MEMO信息失败");
        auto pos = input.find(separator, first_pos);
        if (pos == string::npos) {
            eosio_assert(!required, "解析MEMO信息错误");
            return string::npos;
        }
        *output = input.substr(first_pos, pos - first_pos);
        return pos;
    }

    double get_decimal(uint64_t data)
    {
        return double(data) / double(10000);
    }

    const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    const int8_t mapBase58[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
            -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
            22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
            -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
            47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    };

    struct signup_public_key {
        uint8_t        type;
        array<unsigned char,33> data;
    };
    struct permission_level_weight {
        permission_level permission;
        uint16_t weight;
    };
    struct key_weight {
        signup_public_key key;
        uint16_t weight;
    };
    struct wait_weight {
        uint32_t wait_sec;
        uint16_t weight;
    };
    struct authority {
        uint32_t threshold;
        vector<key_weight> keys;
        vector<permission_level_weight> accounts;
        vector<wait_weight> waits;
    };
    struct newaccount {
        name creator;
        name name;
        authority owner;
        authority active;
    };

    template <class T>inline void hash_combine(std::size_t& seed, const T& v) {
        std::hash<T> hasher;
        seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }

    string to_hex(const char* d, uint32_t s) {
        std::string r;
        const char* to_hex = "0123456789abcdef";
        uint8_t* c = (uint8_t*)d;
        for (uint32_t i = 0; i < s; ++i)
            (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
        return r;
    }

    string get_block_id(){
        capi_checksum256 h;
        auto size = transaction_size();
        char buf[size];
        uint32_t read = read_transaction( buf, size );
        eosio_assert( size == read, "read_transaction failed");
        sha256(buf, read, &h);
        auto data = hash_to_hex((char*)h.hash, sizeof(h.hash));
        return data;
    }

   string hash_to_hex(const char* d, uint32_t s) {
        std::string r;
        const char* to_hex = "0123456789abcdef";
        uint8_t* c = (uint8_t*)d;
        for (uint32_t i = 0; i < s; ++i)
            (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
        return r;
    }

    string sha256_to_hex(const capi_checksum256& sha256) {
        return hash_to_hex((char*)sha256.hash, sizeof(sha256.hash));
    }

    uint64_t getRamPrice(uint64_t bytes){
        if(bytes>0){
            auto ramitr = rammarkets.find(symbol("RAMCORE", 4).raw());
            eosio_assert(ramitr != rammarkets.end(), "内存购买失败");
            auto price = ((( 1.0 * ramitr->quote.balance.amount / 10000.0 ) / ( 1.0 + ramitr->base.balance.amount / 1024.0 )) * double(bytes) / 1024.0) * 10000;
            return price;
        }else{
            return 0;
        }

    }

    size_t sub2sep(const string& input,string* output,const char& separator,const size_t& first_pos = 0,const bool& required = false) {
        eosio_assert(first_pos != string::npos, "解析备注信息失败");
        auto pos = input.find(separator, first_pos);
        if (pos == string::npos) {
            eosio_assert(!required, "解析备注信息错误");
            return string::npos;
        }
        *output = input.substr(first_pos, pos - first_pos);
        return pos;
    }

    bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
    {
        while (*psz && isspace(*psz))
            psz++;
        int zeroes = 0;
        int length = 0;
        while (*psz == '1') {
            zeroes++;
            psz++;
        }
        int size = strlen(psz) * 733 /1000 + 1; 
        std::vector<unsigned char> b256(size);
        static_assert(sizeof(mapBase58)/sizeof(mapBase58[0]) == 256, "mapBase58.size() should be 256"); 
        while (*psz && !isspace(*psz)) {
            int carry = mapBase58[(uint8_t)*psz];
            if (carry == -1) 
                return false;
            int i = 0;
            for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
                carry += 58 * (*it);
                *it = carry % 256;
                carry /= 256;
            }
            assert(carry == 0);
            length = i;
            psz++;
        }
        while (isspace(*psz))
            psz++;
        if (*psz != 0)
            return false;
        std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
        while (it != b256.end() && *it == 0)
            it++;
        vch.reserve(zeroes + (b256.end() - it));
        vch.assign(zeroes, 0x00);
        while (it != b256.end())
            vch.push_back(*(it++));
        return true;
    }

    bool decode_base58(const string& str, vector<unsigned char>& vch) {
        return DecodeBase58(str.c_str(), vch);
    }

    uint64_t mining(uint64_t mining_count)
    {
        if(mining_count>=0 && mining_count<=15000000000){
            return 100UL;
        }else if(mining_count>15000000000 && mining_count<=30000000000){
            return 70UL;
        }else if(mining_count>30000000000 && mining_count<=60000000000){
            return 50UL;
        }else if(mining_count>60000000000 && mining_count<=90000000000){
            return 20UL;
        }else if(mining_count>90000000000 && mining_count<=150000000000){
            return 10UL;
        }else if(mining_count>150000000000 && mining_count<=210000000000){
            return 5UL;
        }else if(mining_count>210000000000 && mining_count<=300000000000){
            return 1UL;
        }else
        {
            return 0UL;
        }
    }

    uint64_t get_next_drawing_id()
    {
        auto gameitr = games.begin();
        games.modify(gameitr, get_self(), [&](auto &s) {
            s.total_drawing_count++;
        });
        return gameitr->total_drawing_count;
    }   

    uint64_t get_next_transfer_id()
    {
        auto gameitr = games.begin();
        games.modify(gameitr, get_self(), [&](auto &s) {
            s.total_transfer_count++;
        });
        return gameitr->total_transfer_count;
    }  

    uint64_t get_next_hatching_id()
    {
        auto gameitr = games.begin();
        games.modify(gameitr, get_self(), [&](auto &s) {
            s.total_hatching_count++;
        });
        return gameitr->total_hatching_count;
    }  
    
    uint64_t get_next_identity_id()
    {
        auto gameitr = games.begin();
        games.modify(gameitr, get_self(), [&](auto &s) {
            s.total_identity_count++;
        });
        return gameitr->total_identity_count;
    }  

    // 内存数据
    TABLE exchange_state {
      asset supply;
      struct connector 
      {
         asset balance;
         double weight = .5;
         EOSLIB_SERIALIZE( connector, (balance)(weight) )
      };
      connector base;
      connector quote;
      uint64_t primary_key()const { return supply.symbol.raw(); }
      EOSLIB_SERIALIZE( exchange_state, (supply)(base)(quote) )
   };
   typedef eosio::multi_index< "rammarket"_n, exchange_state > rammarket;
   rammarket rammarkets;

    // 游戏统计
    TABLE game {
      uint64_t id;
      uint64_t team_fee;               // 团队累计利润
      uint64_t stake_fee;              // 质押累计分红
      uint64_t bidding_fee;            // 竞拍累计分红
      uint64_t referrer_fee;           // 推荐累计分红
      uint64_t team_jackpot;           // 团队奖池数量
      uint64_t bidding_jackpot;        // 竞拍奖池数量
      uint64_t parallel_count;         // 并行处理数量
      uint64_t stake_time;             // 质押分红时间
      uint64_t stake_owner;            // 质押分红账号
      uint64_t stake_token;            // 质押代币数量
      uint64_t stake_token_mirror;     // 质押代币镜像
      uint64_t stake_jackpot;          // 质押奖池数量
      uint64_t stake_jackpot_mirror;   // 质押奖池镜像
      uint64_t total_sell_count;       // 鹅蛋销售数量
      uint64_t total_hatch_count;      // 鹅蛋孵化数量
      uint64_t total_order_count;      // 队列订单数量
      uint64_t total_player_count;     // 鹅蛋玩家数量
      uint64_t total_mining_count;     // 系统挖矿数量
      uint64_t total_counter_count;    // 并发窗口数量
      uint64_t total_drawing_count;    // 系统结算数量
      uint64_t total_hatching_count;   // 系统孵化数量
      uint64_t total_transfer_count;   // 系统交易数量
      uint64_t total_identity_count;   // 系统身份数量
      uint64_t primary_key() const { return id; }
    };
    typedef multi_index<"games"_n, game> _game;
    _game games;  

    // 系统设置
    TABLE setting {
      uint64_t id;                     // id
      uint64_t is_buying;              // 允许购买
      uint64_t is_mining;              // 允许挖矿
      uint64_t is_bidding;             // 允许竞拍
      uint64_t is_staking;             // 允许质押
      uint64_t is_hatching;            // 允许孵化
      uint64_t hatch_max;              // 孵化最大概率95
      uint64_t hatch_water;            // 孵化系统抽水0
      uint64_t hatch_chance;           // 孵化概率点数100
      uint64_t stake_time_offset;      // 质押分红间隔
      uint64_t stake_time_redeem;      // 质押赎回间隔
      uint64_t stake_share_ratio;      // 质押分红比例
      uint64_t eosio_stake_cpu;        // 抵押CPU
      uint64_t eosio_stake_net;        // 抵押NET
      uint64_t eosio_stake_ram;        // 抵押RAM
      uint64_t eosio_stake_max;        // 抵押最大金额
      uint64_t eosio_stake_time;       // 免费抵押时间
      uint64_t primary_key() const { return id; }
    };
    typedef multi_index<"settings"_n, setting> _setting;
    _setting settings;

    // 鹅蛋设置
    TABLE egg {
      uint64_t id;                     // 短账号长度   = 1-10位
      name name_suffix;                // 短号后缀
      uint64_t min_price;              // 售价最低限制
      uint64_t max_price;              // 售价最高限制
      uint64_t sold_count;             // 市场已售数量 = 注册账号数量
      uint64_t hatch_count;            // 市场已孵化量 = 当前市场正售数量
      uint64_t queue_count;            // 等待孵化数量 = 队列等待数量
      uint64_t consume_count;          // 孵化消耗数量 = 玩家自己孵化所消耗的数量
      uint64_t sell_price;             // 官方固定售价 = 为0不固定，大于0则固定
      uint64_t pack_price;             // 鹅蛋合成单价 = 点数1-95 * 单价
      uint64_t pack_condition;         // 需要下级蛋壳数量
      uint64_t pack_is_double;         // 单价是否需要加倍
      uint64_t delay_time;             // 此位数短号孵化等待时间（秒）
      uint64_t delay_multiple;         // 是否孵化时间按合成概率加倍增加
      uint64_t team_ratio;             // 团队分红比例
      uint64_t proxy_ratio;            // 代销分红比例
      uint64_t stake_ratio;            // 质押分红比例
      uint64_t bidding_ratio;          // 竞拍分红比例
      uint64_t referrer_ratio;         // 推荐分红比例
      uint64_t primary_key() const { return id; }
      uint64_t by_suffix() const{ return name_suffix.value;}

      fixed_bytes<32> by_length() const { return length_key(name_suffix,id); }
      static fixed_bytes<32> length_key(name owner,uint64_t length) {
          return fixed_bytes<32>::make_from_word_sequence<uint64_t>(owner.value,length);
      }
    };
    typedef multi_index<"eggs"_n, egg,
    indexed_by<"bysuffix"_n, const_mem_fun<egg, uint64_t, &egg::by_suffix>>,
    indexed_by<"bylength"_n, const_mem_fun<egg, fixed_bytes<32>, &egg::by_length>>
    > _egg;
    _egg eggs;  

    // 玩家信息
    TABLE player{
      uint64_t id;                     // Id
      name owner;                      // 账号
      name referrer;                   // 推荐人
      uint64_t sell_count;             // 销售数量
      uint64_t sell_profit;            // 售蛋获利金额
      uint64_t hatch_time;             // 最后孵化时间
      uint64_t hatch_count;            // 已经孵化数量
      uint64_t hatch_amount;           // 孵化投入金额
      uint64_t proxy_ratio;            // 代销比例
      uint64_t proxy_profit;           // 代销利润
      uint64_t stake_amount;           // 质押代币数量
      uint64_t stake_profit;           // 质押获得分红
      uint64_t unstake_time;           // 质押锁定时间
      uint64_t unstake_amount;         // 质押锁定数量
      uint64_t mining_amount;          // 孵化矿产数量
      uint64_t referrer_profit;        // 推荐人获利
      uint64_t modify_time;            // 修改价格时间
      uint64_t primary_key() const { return id; }
      uint64_t by_owner() const{ return owner.value;}
    };
    typedef multi_index<"players"_n, player,
    indexed_by<"byowner"_n, const_mem_fun<player, uint64_t, &player::by_owner>>
    > _player;
    _player players;    

    // 孵蛋队列
    TABLE order {
      uint64_t id;                     // id
      name owner;                      // 玩家账号
      uint64_t delay_time;             // 等待秒数
      uint64_t count_index;            // 服务台id
      uint64_t name_length;            // 孵化位数
      uint64_t hatch_price;            // 孵化金额
      uint64_t hatch_count;            // 孵化数量
      uint64_t hatch_status;           // 孵化状态 = 0:待孵化，1:孵化中，2:已孵化
      uint64_t hatch_number;           // 蛋壳数量
      uint64_t result_number;          // 实际蛋壳
      string result_hashcode;          // 哈希种子
      time_point order_time;           // 下单时间
      time_point start_time;           // 开始孵化时间
      time_point hatch_time;           // 结束孵化时间
      uint64_t primary_key() const { return id; }
      uint64_t by_status() const {return hatch_status;}

      fixed_bytes<32> by_length() const { return length_key(hatch_status,name_length); }
      static fixed_bytes<32> length_key(uint64_t hatch_status,uint64_t name_length) {
          return fixed_bytes<32>::make_from_word_sequence<uint64_t>(hatch_status,name_length);
      }

    };
    typedef multi_index<"orders"_n, order,
    indexed_by<"bystatus"_n, const_mem_fun<order, uint64_t, &order::by_status>>,
    indexed_by<"bylength"_n, const_mem_fun<order, fixed_bytes<32>, &order::by_length>>
    > _order;
    _order orders;  

    // 售蛋市场
    TABLE market {
      uint64_t id;                     // id
      name owner;                      // 玩家账号
      uint64_t count;                  // 孵化数量
      uint64_t price;                  // 账号价格
      uint64_t length;                 // 账号长度
      uint64_t primary_key() const { return id; }
      uint64_t by_length() const {return length;}

      fixed_bytes<32> by_owner() const { return owner_key(owner,length); }
      static fixed_bytes<32> owner_key(name owner,uint64_t length) {
          return fixed_bytes<32>::make_from_word_sequence<uint64_t>(owner.value,length);
      }
    };
    typedef multi_index<"markets"_n, market,
    indexed_by<"bylength"_n, const_mem_fun<market, uint64_t, &market::by_length>>,
    indexed_by<"byowner"_n, const_mem_fun<market, fixed_bytes<32>, &market::by_owner>>
    > _market;
    _market markets;

    // 玩家店铺 
    TABLE store {
      uint64_t id;                     // id
      name owner;                      // 玩家账号
      uint64_t egg_count;              // 拥有数量
      uint64_t egg_price;              // 账号定价
      uint64_t egg_length;             // 账号长度
      uint64_t sold_count;             // 市场已售数量
      uint64_t hatch_count;            // 市场已孵化量
      uint64_t queue_count;            // 等待孵化数量
      uint64_t consume_count;          // 自己消耗数量
      uint64_t sold_amount;            // 累计售出金额
      uint64_t hatch_amount;           // 累计孵化金额
      uint64_t profit_amount;          // 累计利润金额

      uint64_t primary_key() const { return id; }
      uint64_t by_owner() const{ return owner.value;}
      
      fixed_bytes<32> by_length() const { return length_key(owner,egg_length); }
      static fixed_bytes<32> length_key(name owner,uint64_t egg_length) {
          return fixed_bytes<32>::make_from_word_sequence<uint64_t>(owner.value,egg_length);
      }

      fixed_bytes<32> by_price() const { return price_key(egg_length,egg_price); }
      static fixed_bytes<32> price_key(uint64_t egg_length,uint64_t egg_price) {
          return fixed_bytes<32>::make_from_word_sequence<uint64_t>(egg_length,egg_price);
      }

      fixed_bytes<32> by_owner_price() const { return owner_price_key(owner,egg_length,egg_price); }
      static fixed_bytes<32> owner_price_key(name owner,uint64_t egg_length,uint64_t egg_price) {
          return fixed_bytes<32>::make_from_word_sequence<uint64_t>(owner.value,egg_length,egg_price);
      }
    };
    typedef multi_index<"stores"_n, store,
    indexed_by<"byowner"_n, const_mem_fun<store, uint64_t, &store::by_owner>>,
    indexed_by<"bylength"_n, const_mem_fun<store, fixed_bytes<32>, &store::by_length>>,
    indexed_by<"byprice"_n, const_mem_fun<store, fixed_bytes<32>, &store::by_price>>,
    indexed_by<"byownerprice"_n, const_mem_fun<store, fixed_bytes<32>, &store::by_owner_price>>
    > _store;
    _store stores;  

    // 窗口服务台
    TABLE counter {
      uint64_t id;                    // 服务台id
      uint64_t order_id;              // 订单id
      uint64_t is_using;              // 是否使用
      uint64_t primary_key() const { return id; }
      uint64_t by_using() const {return is_using;}
    };
    typedef multi_index<"counters"_n, counter,
    indexed_by<"byusing"_n, const_mem_fun<counter, uint64_t, &counter::by_using>>
    > _counter;
    _counter counters;  

    // 账号列表
    TABLE suffix {
      name symbol;                    // 账号后缀
      uint64_t primary_key() const { return symbol.value; }
    };
    typedef multi_index<"suffixes"_n, suffix> _suffix;
    _suffix suffixes;  

    //孵化操作
    void buy(name from, asset quantity, string memo){
       require_auth(from);

       name seller;
       name proxy;
       uint64_t stake_ram;
       uint64_t stake_cpu;
       uint64_t stake_net;
       string public_key;
       string account_name;

       // 解析数据 
       parse_name(memo,&seller,&proxy,&account_name,&public_key,&stake_ram,&stake_cpu,&stake_net);

       // 验证数据
       consume_name(quantity,seller,from,proxy,account_name,public_key,stake_ram,stake_cpu,stake_net);
    }

    // 购买鹅蛋 BUYER+eegg.io+drizzle.r+EOS7vwLoyADunPt91GimjjPP5v7Rj38mYebLA2vATxeT4hmbuWmJr+0+0+0+eosiodrizzle
    void parse_name(string memo,name* seller,name* proxy,string* account_name,string* public_key,uint64_t* stake_ram,uint64_t* stake_cpu,uint64_t* stake_net)
    {
        size_t postion;
        string data;
        auto pluscount = count(memo.begin(),memo.end(),'+');
        eosio_assert(pluscount>=6, "缺少加号分隔符");
        memo.erase(std::remove_if(memo.begin(),memo.end(),[](unsigned char x) { return std::isspace(x); }),memo.end());

        // 获取前缀
        postion = string_split(memo, &data, '+', 0, true);
        eosio_assert(data.size()>0, "前缀符号不能为空");

        // 卖家名称
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "卖家账号不能为空");
        *seller = name(data);

        // 注册账号
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "注册账号不能为空");
        *account_name = data;

        // 账号公钥
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "账号公钥不能为空");
        *public_key = data;

        // 账号ram
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "抵押RAM不能为空");
        *stake_ram = stoull(data);

        // 账号cpu
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "抵押CPU不能为空");
        *stake_cpu = stoull(data);

        // 账号net
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "抵押NET不能为空");
        *stake_net = stoull(data);

        // 代销人
        data = memo.substr(++postion);
        *proxy = get_self();
        if(data.size()>0){
            *proxy = name(data);
        }
    }

    // 注册账号
    void consume_name(asset quantity,name seller,name buyer,name proxy,string account_name,string public_key,uint64_t stake_ram,uint64_t stake_cpu,uint64_t stake_net)
    {
        auto gameitr = games.begin();        
        auto settingitr = settings.begin();
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
        eosio_assert(settingitr->is_buying==1, "注册账号功能未启用" );

        //eosio_assert(account_name.size()>=12, "暂时仅允许注册10位账号");

        // 验证后缀
        eosio_assert(account_name.size()>2 && account_name.size()<=12, "无效的账号名称");
        auto name_suffix = name(account_name.substr(account_name.size()-2,2));
        auto suffixitr = suffixes.find(name_suffix.value);
        eosio_assert(suffixitr!=suffixes.end(), "账号后缀不存在");  

        // 获取账号
        transform(account_name.begin(),account_name.end(),account_name.begin(), ::tolower);
        auto account = name(account_name);
        eosio_assert(account_name==account.to_string(), "账号只允许是：数字1到5、小写字母a到z、小数点");
        eosio_assert(!is_account(account), "此账号已经被注册");

        // 获取公钥
        eosio_assert(public_key.size()>0, "公钥不能为空");
        eosio_assert(public_key.size()==53, "公钥长度不正确");
        string pubkey_prefix("EOS");
        auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key.begin());
        eosio_assert(result.first == pubkey_prefix.end(), "公钥缺少EOS前缀");
        auto base58substr = public_key.substr(pubkey_prefix.length());
        vector<unsigned char> vch;
        eosio_assert(decode_base58(base58substr, vch), "反编码公钥失败");
        eosio_assert(vch.size() == 37, "公钥长度不正确");
        array<unsigned char, 33> pubkey_data;
        copy_n(vch.begin(), 33, pubkey_data.begin());
        capi_checksum160 check_pubkey;
        ripemd160(reinterpret_cast<char*>(pubkey_data.data()), 33, &check_pubkey);
        eosio_assert(memcmp(&check_pubkey, &vch.end()[-4], 4) == 0, "输入了无效的公钥");

        // 消耗鹅蛋
        bool is_store_no_egg = false;
        name name_seller;
        uint64_t name_price;
        uint64_t name_length = account_name.size()-2;
        update_long_market_byowner(name_length,&name_price,seller,&name_seller, &is_store_no_egg);
        if(is_store_no_egg==true)
        {
            update_long_market_bylength(name_length,&name_price,&name_seller);
        }
        // if(name_length<=3)
        // {
        //     update_short_market_byowner(name_length,&name_price,seller,&name_seller, &is_store_no_egg);
        //     if(is_store_no_egg==true)
        //     {
        //         update_short_market_byprice(name_length,&name_price,&name_seller);
        //     }
        // }else{
        //     update_long_market_byowner(name_length,&name_price,seller,&name_seller, &is_store_no_egg);
        //     if(is_store_no_egg==true)
        //     {
        //         update_long_market_bylength(name_length,&name_price,&name_seller);
        //     }
        // }

        // 孵化设置
        auto eggitr = eggs.find(name_length);
        eosio_assert(eggitr!=eggs.end(),"孵化设置不存在");
        if(name_length>3)
        {
            name_price = eggitr->sell_price;
        }
        eggs.modify(eggitr,get_self(),[&](auto&s){
            s.sold_count ++;
        });

        // 卖家信息
        auto selleridx = players.get_index<"byowner"_n>();
        auto selleritr = selleridx.find(name_seller.value);
        auto proxy_ratio = get_decimal(200);
        eosio_assert(selleritr!=selleridx.end(),"卖家信息不存在");
        if(selleritr->proxy_ratio>proxy_ratio)
        {
            proxy_ratio = get_decimal(selleritr->proxy_ratio);
        }

        // 质押资源
        asset user_stake_cpu(stake_cpu, CORE_TOKEN);
        asset user_stake_net(stake_net, CORE_TOKEN);
        asset user_stake_ram(stake_ram, CORE_TOKEN);
        asset user_stake_amount = user_stake_ram+user_stake_cpu+user_stake_net;

        asset eosio_stake_cpu(settingitr->eosio_stake_cpu, CORE_TOKEN);
        asset eosio_stake_net(settingitr->eosio_stake_net, CORE_TOKEN);
        asset eosio_stake_ram(getRamPrice(settingitr->eosio_stake_ram), CORE_TOKEN);

        asset total_stake_cpu = eosio_stake_cpu + user_stake_cpu;
        asset total_stake_net = eosio_stake_net + user_stake_net;
        asset total_stake_ram = eosio_stake_ram + user_stake_ram;

        // 计算利润
        auto stake_fee = eosio_stake_ram.amount;// 系统消耗
        auto consume_fee = quantity.amount - user_stake_amount.amount;// 转账单价
        auto proxy_fee = consume_fee * proxy_ratio; // 代销人分红
        auto extra_fee = proxy_fee + stake_fee;// 额外金额
        auto sell_fee = consume_fee - extra_fee;
        eosio_assert(quantity.amount>=user_stake_amount.amount && consume_fee>=name_price,"转账金额不足以注册账号");
        eosio_assert(consume_fee>extra_fee && (consume_fee - extra_fee)>=760, "内存价格过高，请稍后注册");
    
        // 更新分红
        auto proxyidx = players.get_index<"byowner"_n>();
        auto proxyitr = proxyidx.find((is_store_no_egg && seller!=get_self() ?seller.value:proxy.value));
        if(proxyitr!=proxyidx.end())
        {
            proxyidx.modify(proxyitr,get_self(),[&](auto&s){
                s.proxy_profit+=proxy_fee;
            });
        }
        selleridx.modify(selleritr,get_self(),[&](auto&s){
            s.sell_count+=1;
            s.sell_profit+=sell_fee;
        });

        // 更新店铺
        auto storeidx = stores.get_index<"bylength"_n>();
        auto storeitr = storeidx.find(store::length_key(name_seller,name_length));
        if(storeitr!=storeidx.end() && storeitr->owner==name_seller && storeitr->egg_length == name_length && storeitr->egg_count>0)
        {
            storeidx.modify(storeitr,get_self(),[&](auto&s){
                if(name_length<=3 && storeitr->egg_count==1)
                {
                    s.egg_price=0;
                }
                s.egg_count--;
                s.sold_count++;
                s.sold_amount+=consume_fee;
                s.profit_amount+=sell_fee;
            });
        }

        // 更新统计
        games.modify(gameitr,get_self(),[&](auto&s){
            s.total_sell_count+=1;
        });

        // 获取短号
        auto owner_suffix = name(account_name.substr(account_name.size()-1,1));


        // 注册短号
        signup_public_key pubkey = {
            .type = 0,
            .data = pubkey_data,
        };
        key_weight pubkey_weight = {
            .key = pubkey,
            .weight = 1,
        };
        authority owner = authority{
            .threshold = 1,
            .keys = {pubkey_weight},
            .accounts = {},
            .waits = {}
        };
        authority active = authority{
            .threshold = 1,
            .keys = {pubkey_weight},
            .accounts = {},
            .waits = {}
        };
        newaccount new_account = newaccount{
            .creator = owner_suffix, 
            .name = account,
            .owner = owner,
            .active = active
        };

        action(
                permission_level{ owner_suffix, "eegg.io"_n },
                "eosio"_n,
                "newaccount"_n,
                new_account
        ).send();

        action(
                permission_level{ get_self(), "active"_n},
                "eosio"_n,
                "buyram"_n,
                make_tuple(get_self(), account, total_stake_ram)
        ).send();

        if(user_stake_net.amount>0 && user_stake_cpu.amount>0)
        {
            transaction selfstaker;
            selfstaker.actions.emplace_back(permission_level{get_self(),"active"_n},"eosio"_n,"delegatebw"_n,make_tuple(get_self(),account,user_stake_net,user_stake_cpu,true));
            selfstaker.delay_sec = 0;
            selfstaker.send(get_next_transfer_id(),get_self(),false);
        }

        if(eosio_stake_net.amount>0 && eosio_stake_cpu.amount>0)
        {
            transaction eosiostaker;
            eosiostaker.actions.emplace_back(permission_level{get_self(),"active"_n},"eosio"_n,"delegatebw"_n,make_tuple(get_self(),account,eosio_stake_net,eosio_stake_cpu,false));
            eosiostaker.delay_sec = 0;
            eosiostaker.send(get_next_transfer_id(),get_self(),false);

            transaction eosiounstaker;
            eosiounstaker.actions.emplace_back(permission_level{get_self(),"active"_n},"eosio"_n,"undelegatebw"_n,make_tuple(get_self(),account,eosio_stake_net,eosio_stake_cpu));
            eosiounstaker.delay_sec = settingitr->eosio_stake_time;
            eosiounstaker.send(get_next_transfer_id(),get_self(),false);

        }

        // 分红转账
        if(proxy_fee>0 && (is_store_no_egg && seller!=get_self()?seller:proxy)!=get_self())
        {
            transaction transfer1;    
            string remark ="获得短账号注册推荐分红";
            remark.append(REMARK);
            asset proxyfee(proxy_fee,CORE_TOKEN);
            transfer1.actions.emplace_back(permission_level {get_self(), "active"_n }, CORE_ACCOUNT, "transfer"_n, std::make_tuple(get_self(), (is_store_no_egg && seller!=get_self()?seller:proxy), proxyfee, remark));
            transfer1.delay_sec = 0;
            transfer1.send(get_next_drawing_id(), get_self(), false); 
        }
        if(sell_fee>0)
        {
            transaction transfer2;    
            string remark ="恭喜您，获得了丰厚的售蛋回报！";
            remark.append(REMARK);
            asset sellfee(sell_fee,CORE_TOKEN);
            transfer2.actions.emplace_back(permission_level {get_self(), "active"_n }, CORE_ACCOUNT, "transfer"_n, std::make_tuple(get_self(), name_seller, sellfee, remark));
            transfer2.delay_sec = 0;
            transfer2.send(get_next_drawing_id(), get_self(), false); 
        }
    }

    // 1-3位市场消耗
    // void update_short_market_byowner(uint64_t name_length,uint64_t* name_price,name seller,name* name_seller, bool* is_store_no_egg)
    // {
    //     auto storeidx = stores.get_index<"byownerprice"_n>();
    //     auto storeitr = storeidx.lower_bound(store::owner_price_key(seller,name_length,10000));
    //     if(storeitr!=storeidx.end() && storeitr->owner==seller && storeitr->egg_length == name_length && storeitr->egg_count>0 && storeitr->egg_price>=10000)
    //     {
    //         auto marketidx = markets.get_index<"byowner"_n>();
    //         auto marketitr = marketidx.find(market::owner_key(seller,name_length));
    //         if(marketitr!=marketidx.end() && marketitr->owner==seller && marketitr->length==name_length)
    //         {
    //             *name_price = marketitr->price;
    //             *name_seller = marketitr->owner;
    //             marketidx.erase(marketitr); 
    //         }else
    //         {
    //             *is_store_no_egg = true;
    //         }
    //     }else
    //     {
    //         *is_store_no_egg = true;
    //     }
    // }

    // 1-3位市场消耗
    // void update_short_market_byprice(uint64_t name_length,uint64_t* name_price,name* name_seller)
    // {
    //     auto storeidx = stores.get_index<"byprice"_n>();
    //     auto storeitr = storeidx.lower_bound(store::price_key(name_length,10000));
    //     if(storeitr!=storeidx.end() && storeitr->egg_length == name_length && storeitr->egg_count>0 && storeitr->egg_price>=10000)
    //     {
    //         auto marketidx = markets.get_index<"byowner"_n>();
    //         auto marketitr = marketidx.find(market::owner_key(storeitr->owner,name_length));
    //         eosio_assert(marketitr!=marketidx.end() && marketitr->owner==storeitr->owner && marketitr->length==name_length,"暂无可用注册账号的鹅蛋");
    //         *name_price = marketitr->price;
    //         *name_seller = marketitr->owner;
    //         marketidx.erase(marketitr); 
    //     }else
    //     {
    //         eosio_assert(false,"暂无可用注册账号的鹅蛋");
    //     }
    // }

    // 1-10位市场消耗
    void update_long_market_byowner(uint64_t name_length,uint64_t* name_price,name seller,name* name_seller, bool* is_store_no_egg)
    {
        auto marketidx = markets.get_index<"byowner"_n>();
        auto marketitr = marketidx.lower_bound(market::owner_key(seller,name_length));
        if(marketitr!=marketidx.end() && marketitr->owner==seller && marketitr->length==name_length)
        {
            *name_price = marketitr->price;
            *name_seller = marketitr->owner;
            marketidx.erase(marketitr); 
        }else
        {
            *is_store_no_egg = true;
        }
    }

    // 1-10位市场消耗
    void update_long_market_bylength(uint64_t name_length,uint64_t* name_price,name* name_seller)
    {
        auto marketidx = markets.get_index<"bylength"_n>();
        auto marketitr = marketidx.lower_bound(name_length);
        eosio_assert(marketitr!=marketidx.end() && marketitr->length==name_length,"暂无可用注册账号的鹅蛋");
        *name_price = marketitr->price;
        *name_seller = marketitr->owner;
        marketidx.erase(marketitr); 
    }

    // 注册账号
    void reg_name(string payment,string account_name,string account_suffix,string public_key)
    {
        require_auth(DRAW_ACCOUNT);

        auto gameitr = games.begin();        
        auto settingitr = settings.begin();
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
        eosio_assert(settingitr->is_buying==1, "注册账号功能未启用" );

        // 验证长度
        auto isShortAccount = account_name.size()>1 && account_name.size()<=10 && account_suffix.size()>=2;
        auto isNormalAccount = account_name.size()==12 && account_suffix.size()==0;
        eosio_assert(isShortAccount || isNormalAccount, "无效的账号名称");

        // 验证账号
        string combine_account = account_name+account_suffix;
        auto creeate_account = name(combine_account);
        if(isShortAccount){
            auto name_suffix = name(account_suffix);
            auto suffixitr = suffixes.find(name_suffix.value);
            eosio_assert(suffixitr!=suffixes.end(), "账号后缀不存在");  
        }
        eosio_assert(combine_account==creeate_account.to_string(), "账号只允许是：数字1到5、小写字母a到z、小数点");
        eosio_assert(!is_account(creeate_account), "此账号已经被注册");

        // 验证公钥
        eosio_assert(public_key.size()>0, "公钥不能为空");
        eosio_assert(public_key.size()==53, "公钥长度不正确");
        string pubkey_prefix("EOS");
        auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key.begin());
        eosio_assert(result.first == pubkey_prefix.end(), "公钥缺少EOS前缀");
        auto base58substr = public_key.substr(pubkey_prefix.length());
        vector<unsigned char> vch;
        eosio_assert(decode_base58(base58substr, vch), "反编码公钥失败");
        eosio_assert(vch.size() == 37, "公钥长度不正确");
        array<unsigned char, 33> pubkey_data;
        copy_n(vch.begin(), 33, pubkey_data.begin());
        capi_checksum160 check_pubkey;
        ripemd160(reinterpret_cast<char*>(pubkey_data.data()), 33, &check_pubkey);
        eosio_assert(memcmp(&check_pubkey, &vch.end()[-4], 4) == 0, "输入了无效的公钥");

        // 获取创建者
        auto owner_tag = "active"_n;
        auto owner_suffix = get_self();
        if(isShortAccount)
        {
            owner_tag = "eegg.io"_n;
            owner_suffix = name(account_suffix.erase(0,1));
        }

        // 质押额度
        asset eosio_stake_ram(getRamPrice(settingitr->eosio_stake_ram), CORE_TOKEN);
        asset eosio_stake_cpu(settingitr->eosio_stake_cpu, CORE_TOKEN);
        asset eosio_stake_net(settingitr->eosio_stake_net, CORE_TOKEN);

        // 注册短号
        signup_public_key pubkey = {
            .type = 0,
            .data = pubkey_data,
        };
        key_weight pubkey_weight = {
            .key = pubkey,
            .weight = 1,
        };
        authority owner = authority{
            .threshold = 1,
            .keys = {pubkey_weight},
            .accounts = {},
            .waits = {}
        };
        authority active = authority{
            .threshold = 1,
            .keys = {pubkey_weight},
            .accounts = {},
            .waits = {}
        };
        newaccount new_account = newaccount{
            .creator = owner_suffix, 
            .name = creeate_account,
            .owner = owner,
            .active = active
        };

        action(
                permission_level{ owner_suffix, owner_tag },
                "eosio"_n,
                "newaccount"_n,
                new_account
        ).send();

        action(
                permission_level{ get_self(), "active"_n},
                "eosio"_n,
                "buyram"_n,
                make_tuple(get_self(), creeate_account, eosio_stake_ram)
        ).send();


        if(eosio_stake_net.amount>0 && eosio_stake_cpu.amount>0)
        {
            transaction eosiostaker;
            eosiostaker.actions.emplace_back(permission_level{get_self(),"active"_n},"eosio"_n,"delegatebw"_n,make_tuple(get_self(),creeate_account,eosio_stake_net,eosio_stake_cpu,false));
            eosiostaker.delay_sec = 0;
            eosiostaker.send(get_next_transfer_id(),get_self(),false);

            transaction eosiounstaker;
            eosiounstaker.actions.emplace_back(permission_level{get_self(),"active"_n},"eosio"_n,"undelegatebw"_n,make_tuple(get_self(),creeate_account,eosio_stake_net,eosio_stake_cpu));
            eosiounstaker.delay_sec = settingitr->eosio_stake_time;
            eosiounstaker.send(get_next_transfer_id(),get_self(),false);

        }
    }

    //竞拍操作
    void bid(name from, asset quantity){
       require_auth(from);

    }

    //团队分红
    void teamdivide(uint64_t id,uint64_t timestamp)
    {
        cancel_deferred(id);

        transaction transfer; 
        transfer.actions.emplace_back(permission_level{get_self(), "active"_n}, get_self(), "teambonus"_n, std::make_tuple(current_time())); 
        transfer.delay_sec = timestamp;
        transfer.send(id, get_self(), false); 
    }

    //质押分红
    void stakedivide(uint64_t id,uint64_t timestamp)
    {
        cancel_deferred(id);
        
        transaction transfer; 
        transfer.actions.emplace_back(permission_level{get_self(), "active"_n}, get_self(), "stakebonus"_n, std::make_tuple(current_time())); 
        transfer.delay_sec = timestamp;
        transfer.send(id, get_self(), false); 
    }

    //质押代币
    void stake(name from, asset quantity) {
       require_auth(from);

       auto gameitr = games.begin();
       auto settingitr = settings.begin();
       eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
       eosio_assert(settingitr->is_staking==1, "质押功能未启用" ); 

       auto playeridx = players.get_index<"byowner"_n>();
       auto playeritr = playeridx.find(from.value);
       eosio_assert(playeritr != playeridx.end() , "孵蛋后才能质押" );

       playeridx.modify(playeritr, get_self(), [&](auto &s) {
          s.stake_amount += quantity.amount;
       });

       games.modify(gameitr,get_self(),[&](auto &s){
          s.stake_token += quantity.amount;
       }); 
    }

    //孵化操作
    void hatch(name from, asset quantity, string memo){
       require_auth(from);

       name referrer;
       uint64_t hatch_count;            
       uint64_t hatch_length;
       uint64_t hatch_number;

       // 解析数据 
       parse_data(memo,&hatch_length,&hatch_count,&hatch_number,&referrer);

       // 验证数据
       save_data(from,quantity,hatch_length,hatch_count,hatch_number,referrer);
    }

    // 解析孵化 HATCH+95+4+10+stardustcore
    void parse_data(string memo,uint64_t* hatch_length,uint64_t* hatch_count,uint64_t* hatch_number,name* referrer)
    {
        size_t postion;
        string data;
        auto pluscount = count(memo.begin(),memo.end(),'+');
        eosio_assert(pluscount>=3, "缺少加号分隔符");
        memo.erase(std::remove_if(memo.begin(),memo.end(),[](unsigned char x) { return std::isspace(x); }),memo.end());

        // 获取前缀
        postion = string_split(memo, &data, '+', 0, true);
        eosio_assert(data.size()>0, "前缀符号不能为空");

        // 获取蛋壳
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "蛋壳数量不能为空");
        eosio_assert(is_digits(data), "蛋壳数量必须是数字");
        *hatch_number = stoull(data);

        // 获取长度
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "孵化位数不能为空");
        eosio_assert(is_digits(data), "孵化位数必须是数字");
        *hatch_length = stoull(data);

        // 获取数量
        postion = string_split(memo, &data, '+', ++postion, true);
        eosio_assert(data.size()>0, "孵化数量不能为空");
        eosio_assert(is_digits(data), "孵化数量必须是数字");
        *hatch_count = stoull(data);

        // 获取推荐人
        data = memo.substr(++postion);
        *referrer = get_self();
        if(data.size()>0)
        {
            *referrer = name(data);
        }
    }

    // 保存数据
    void save_data(name from,asset quantity,uint64_t hatch_length,uint64_t hatch_count,uint64_t hatch_number,name referrer)
    {
        // 系统设置
        auto gameitr = games.begin();        
        auto settingitr = settings.begin();
        auto eggitr = eggs.find(hatch_length);
        eosio_assert(eggitr!=eggs.end(),"孵化设置不存在");
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
        eosio_assert(settingitr->is_hatching==1, "孵化功能未启用" ); 
        eosio_assert(hatch_count<=100, "孵化数量超过最大值");
        eosio_assert(hatch_length>=1 && hatch_length<=10, "账号孵化长度必须在1-10位之间" ); 
        eosio_assert(hatch_number>=1 && hatch_number<=settingitr->hatch_max, "蛋壳数量必须在1-95之间" ); 
        auto hatch_price = eggitr->pack_price * hatch_number * hatch_count;
        eosio_assert(quantity.amount>=hatch_price,"转账金额不能低于孵化金额");

        // 更新店铺
        auto storeidx = stores.get_index<"bylength"_n>();
        auto storeitr = storeidx.find(store::length_key(from,hatch_length));
        if(storeitr!=storeidx.end() && storeitr->owner==from && storeitr->egg_length==hatch_length)
        {
            storeidx.modify(storeitr,get_self(),[&](auto&s){
                s.queue_count +=hatch_count;
                s.hatch_amount += quantity.amount;
            });
        }else
        {
            stores.emplace(get_self(),[&](auto&s){
                s.id = stores.available_primary_key();
                s.owner = from;
                s.egg_length = hatch_length;
                s.egg_price = eggitr->sell_price;
                s.queue_count = hatch_count;
                s.hatch_amount = quantity.amount;
            });
        }

        // 孵化设置
        eggs.modify(eggitr,get_self(),[&](auto&s){
            s.queue_count +=hatch_count;
        });
        // if(hatch_length<4)
        // {
        //     auto lower_length = hatch_length+1;
        //     auto lower_condition = eggitr->pack_condition * hatch_count;
        //     auto lowerstoreitr = storeidx.find(store::length_key(from,lower_length));
        //     if(lowerstoreitr!=storeidx.end() && lowerstoreitr->owner==from && lowerstoreitr->egg_length==lower_length && lowerstoreitr->egg_count>=lower_condition)
        //     {
        //         auto lowercount = 0UL;
        //         auto lowermarketidx = markets.get_index<"byowner"_n>();
        //         auto lowermarketitr = lowermarketidx.lower_bound(market::owner_key(from,lower_length));
        //         while( lowermarketitr!=lowermarketidx.end()) 
        //         {
        //             if(lowercount>=lower_condition)break;
        //             if(lowermarketitr->owner==from && lowermarketitr->length==lower_length)
        //             {
        //                 lowercount +=lowermarketitr->count;
        //                 lowermarketitr = lowermarketidx.erase(lowermarketitr);
        //             }else
        //             {
        //                 break;
        //             }
        //         }

        //         auto lowereggitr = eggs.find(lower_length);
        //         eggs.modify(lowereggitr,get_self(),[&](auto&s){
        //             s.consume_count += lower_condition;
        //         });

        //         storeidx.modify(lowerstoreitr,get_self(),[&](auto&s){
        //             s.consume_count+=lower_condition;
        //             if(lowerstoreitr->egg_count>=lower_condition)
        //             {
        //                 s.egg_count -=lower_condition;
        //             }else
        //             {
        //                 s.egg_count =0;
        //             }
        //         });

        //     }else{
        //         string error_message = "至少需要"+to_string(lower_condition)+"个"+to_string(hatch_length+1)+"位蛋才能孵化"+to_string(hatch_count)+"个"+to_string(hatch_length)+"位蛋";
        //         eosio_assert(false,error_message.c_str());
        //     }
        // }

        // 分配利润
        auto team_fee = uint64_t(quantity.amount * get_decimal(eggitr->team_ratio));
        auto stake_fee = uint64_t(quantity.amount * get_decimal(eggitr->stake_ratio));
        auto bidding_fee = uint64_t(quantity.amount * get_decimal(eggitr->bidding_ratio));
        auto referrer_fee = uint64_t(quantity.amount * get_decimal(eggitr->referrer_ratio));
        auto sumation_fee = uint64_t(team_fee + stake_fee + bidding_fee + (referrer!=get_self()?referrer_fee:0));
        auto extra_fee = uint64_t(quantity.amount>=sumation_fee? quantity.amount - sumation_fee:0);
        if(extra_fee>0)team_fee +=extra_fee;
        
        // 玩家信息
        auto is_new_player = false;
        auto mining_count = settingitr->is_mining==1? quantity.amount * mining(gameitr->total_mining_count):0;
        auto playeridx = players.get_index<"byowner"_n>();
        auto playeritr = playeridx.find(from.value);
        if(playeritr == playeridx.end())
        {
            is_new_player = true;
            players.emplace(get_self(), [&](auto& s) {
                s.id = players.available_primary_key();
                s.owner = from;
                s.referrer = referrer;
                s.hatch_time = current_time();
                s.hatch_amount = quantity.amount;
                s.mining_amount = mining_count;
            });
        }else
        {
            playeridx.modify(playeritr, get_self(),[&](auto& s) {
                s.referrer = referrer;
                s.hatch_time = current_time();
                s.hatch_amount += quantity.amount;
                s.mining_amount += mining_count;
            });
        }

        //推荐人累计
        if(referrer!=get_self())
        {
            auto referreridx = players.get_index<"byowner"_n>();
            auto referreritr = referreridx.find(referrer.value);
            if(referreritr != referreridx.end())
            {
                referreridx.modify(referreritr, get_self(),[&](auto& s) {
                    s.referrer_profit += referrer_fee;
                });
            }
        }

        // 保存订单
        auto delay_time = 0UL;
        auto order_time = time_point(microseconds(current_time()));
        if(eggitr->delay_multiple>0)
        {
            delay_time = (eggitr->delay_time + eggitr->delay_multiple * hatch_number);
        }else
        {
            delay_time = eggitr->delay_time;
        }
        for(auto i=0;i<hatch_count;i++)
        {
            orders.emplace(get_self(),[&](auto&s){
                s.id = get_next_identity_id();
                s.owner = from;
                s.delay_time = delay_time;
                s.order_time = order_time;
                s.name_length = hatch_length;
                s.hatch_status = 0;
                s.hatch_count = 1;
                s.hatch_price = uint64_t(quantity.amount/hatch_count);
                s.hatch_number = hatch_number;
            });
        }

        // 统计数据
        games.modify(gameitr,get_self(),[&](auto&s){
            s.team_fee += team_fee;
            s.stake_fee += stake_fee;
            s.bidding_fee += bidding_fee;
            s.referrer_fee += referrer_fee;
            s.team_jackpot += team_fee;
            s.stake_jackpot += stake_fee;
            s.bidding_jackpot += bidding_fee;
            s.total_order_count += hatch_count;
            s.total_player_count += (is_new_player?1:0);
            s.total_mining_count += mining_count;
        });

        hatch_egg();

        if(referrer_fee>0 && referrer!=get_self())
        {
            transaction transfer1;  
            string remark ="获得鹅蛋孵化推荐分红";
            remark.append(REMARK);
            asset referrerfee(referrer_fee,CORE_TOKEN);
            transfer1.actions.emplace_back(permission_level {get_self(), "active"_n }, CORE_ACCOUNT, "transfer"_n, std::make_tuple(get_self(), referrer, referrerfee, remark));
            transfer1.delay_sec = 0;
            transfer1.send(get_next_hatching_id(), get_self(), false); 
        }

        if(mining_count>0)
        {
            transaction transfer2;  
            string remark ="获得鹅蛋挖矿代币EEGG";
            remark.append(REMARK);
            asset miningfee(mining_count,ISSUE_TOKEN);
            transfer2.actions.emplace_back(permission_level {get_self(), "active"_n }, ISSUE_ACCOUNT, "issue"_n, std::make_tuple(from, miningfee, remark));
            transfer2.delay_sec = 0;
            transfer2.send(get_next_hatching_id(), get_self(), false); 
        }
    } 

    // 孵化鹅蛋
    void hatch_egg(){

        // 基础数据
        auto gameitr = games.begin();
        auto settingitr = settings.begin();
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );

        // 查询窗口
        auto maxcounter = 0UL;
        auto start_time = time_point(microseconds(current_time()));
        auto counteritr = counters.begin();
        if(gameitr->total_counter_count<gameitr->parallel_count)
        {
            for(;counteritr!=counters.end();counteritr++)
            {
                if(counteritr->is_using==0)
                {
                    auto orderidx = orders.get_index<"bylength"_n>();
                    auto orderitr = orderidx.lower_bound(order::length_key(0,1));
                    if(orderitr!=orderidx.end() && orderitr->hatch_status==0)
                    {
                        orderidx.modify(orderitr,get_self(),[&](auto&s){
                            s.hatch_status=1;
                            s.count_index = counteritr->id;
                            s.start_time = start_time;
                            s.hatch_time = time_point(microseconds(current_time() + orderitr->delay_time*1000000));;
                        });

                        counters.modify(counteritr,get_self(),[&](auto&s){
                            s.order_id = orderitr->id;
                            s.is_using=1;
                        });

                        games.modify(gameitr,get_self(),[&](auto&s){
                            s.total_counter_count++;
                        });

                    }else
                    {
                        break;
                    }
                }
            }
        }
    }

  public:
    using contract::contract;
    stardustcore(name receiver, name code,  datastream<const char*> ds): 
    contract(receiver, code, ds),
    eggs(receiver, receiver.value),
    games(receiver, receiver.value),
    orders(receiver,receiver.value),
    stores(receiver,receiver.value),
    markets(receiver,receiver.value),
    players(receiver,receiver.value),
    suffixes(receiver,receiver.value),
    counters(receiver,receiver.value),
    settings(receiver, receiver.value),
    rammarkets("eosio"_n, "eosio"_n.value){}
    
    //转账操作
    ACTION transfer(name from, name to, asset quantity, string memo)
    {
        require_auth( from ); 
        require_recipient(LOGS_ACCOUNT);

        if(quantity.is_valid() && quantity.amount > 0 && from != get_self() && to == get_self() && from!=name("eosio.ram") && from!=name("eosio.stake") && from!=name("eosio.rex"))
        {
            if(quantity.symbol == ISSUE_TOKEN)
            {
                if(memo=="BID")
                {
                    bid(from,quantity);
                }
                else if(memo=="STAKE")
                {
                    stake(from,quantity);
                }
            }else if(quantity.symbol == CORE_TOKEN)
            {
                auto prefix = memo.substr(0,5);
                if (prefix=="BUYER")
                {
                    buy(from,quantity,memo);
                }
                else if (prefix=="HATCH")
                {
                    hatch(from,quantity,memo);
                }
            }
        }
    }
    
    // 提取质押分红
    ACTION stakeclaim(name from) 
    {
        require_auth(from);

        auto settingitr = settings.begin();
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
        eosio_assert(settingitr->is_staking==1, "质押功能未启用" ); 

        auto playeridx = players.get_index<"byowner"_n>();
        auto playeritr = playeridx.find(from.value);
        eosio_assert(playeritr != playeridx.end(), "质押账号不存在" );
        eosio_assert(playeritr->stake_profit>0, "没有足够的收益" );

        string remark = "获得质押分红";
        remark.append(REMARK);
        asset dividendfee(playeritr->stake_profit,CORE_TOKEN);
        action(permission_level{get_self(), "active"_n},CORE_ACCOUNT,"transfer"_n,make_tuple(get_self(), from, dividendfee, remark)).send();

        playeridx.modify(playeritr, get_self(), [&](auto &s) {
            s.stake_profit = 0;
        });
    }

    // 延时赎回
    ACTION unstake(name from,asset quantity) 
    {
        require_auth(from);

        auto settingitr = settings.begin();
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
        eosio_assert(settingitr->is_staking==1, "质押功能未启用" ); 
        eosio_assert(quantity.amount>=1000, "金额至少为0.1" );

        auto playeridx = players.get_index<"byowner"_n>();
        auto playeritr = playeridx.find(from.value);
        eosio_assert(playeritr != playeridx.end() , "账户信息不存在" );
        eosio_assert(playeritr->stake_amount>=quantity.amount, "没有可赎回代币" );    

        cancel_deferred(from.value);

        auto unstake_time = now() + settingitr->stake_time_redeem;
        playeridx.modify(playeritr, get_self(), [&](auto &s) {
            if(playeritr->stake_amount>=quantity.amount)
            {
                s.stake_amount -= quantity.amount;
            }else{
                s.stake_amount = 0;
            }
            
            if(now()>playeritr->unstake_time)
            {
                s.unstake_amount = quantity.amount;
            }else
            {
                s.unstake_amount += quantity.amount;
            }
            s.unstake_time = unstake_time;
        });

        auto gameitr = games.begin();
        games.modify(gameitr,get_self(),[&](auto &s){
            if(gameitr->stake_token>=quantity.amount)
            {
                s.stake_token -= quantity.amount;
            }else{
                s.stake_token = 0;
            }
        }); 

        transaction transfer;    
        string remark ="赎回质押代币EEGG";
        remark.append(REMARK);
        asset stakefee(quantity.amount,ISSUE_TOKEN);
        transfer.actions.emplace_back(permission_level {get_self(), "active"_n }, ISSUE_ACCOUNT, "transfer"_n, std::make_tuple(get_self(), from, stakefee, remark));
        transfer.delay_sec = settingitr->stake_time_redeem+5;
        transfer.send(from.value, get_self(), false); 
    }

    // 撤销赎回
    ACTION unstakeoff(name from) 
    {
        require_auth(from);

        auto settingitr = settings.begin();
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );
        eosio_assert(settingitr->is_staking==1, "质押功能未启用" ); 

        auto playeridx = players.get_index<"byowner"_n>();
        auto playeritr = playeridx.find(from.value);
        eosio_assert(playeritr != playeridx.end() , "账户信息不存在" );  
        eosio_assert(playeritr->unstake_amount>0, "没有可撤销的代币" );  
        eosio_assert(playeritr->unstake_time>now(), "已超出可撤销时间" );

        cancel_deferred(from.value);

        auto gameitr = games.begin();
        games.modify(gameitr,get_self(),[&](auto &s){
            s.stake_token += playeritr->unstake_amount;
        }); 

        playeridx.modify(playeritr, get_self(), [&](auto &s) {
            s.stake_amount += playeritr->unstake_amount;
            s.unstake_time = 0;
            s.unstake_amount = 0;
        });

    } 

    // 质押分红
    ACTION stakebonus(uint64_t bonus_time) 
    {
        require_auth(get_self());  
        
        auto count = 0UL;
        auto gameitr = games.begin();
        auto playeritr = players.begin();
        auto settingitr = settings.begin();
        eosio_assert(now()>=gameitr->stake_time, "尚未到达质押分红时间");

        auto timestamp = now();
        auto extratime = timestamp % settingitr->stake_time_offset;
        auto intgertime = timestamp - extratime;
        auto futuretime = intgertime + settingitr->stake_time_offset + 4 * 3600;
        auto delaytime = futuretime - timestamp;
        if(gameitr->stake_jackpot==0 && gameitr->stake_jackpot_mirror==0)
        {
            games.modify(gameitr,get_self(),[&](auto &s){
                s.stake_time = futuretime;
            }); 

            stakedivide(800000000000000,delaytime+5);

        }else
        {
            if(gameitr->stake_owner>0)
            {
                playeritr = players.lower_bound(gameitr->stake_owner);
            }

            if(gameitr->stake_jackpot_mirror==0)
            {
                auto today_amount = gameitr->stake_jackpot * get_decimal(settingitr->stake_share_ratio);
                games.modify(gameitr,get_self(),[&](auto &s){
                    s.stake_token_mirror = gameitr->stake_token;
                    s.stake_jackpot_mirror = today_amount ;
                    if(gameitr->stake_token>0)
                    {
                        if(gameitr->stake_jackpot>=today_amount)
                        {
                            s.stake_jackpot -= today_amount;
                        }else
                        {
                            s.stake_jackpot = 0;
                        }
                    }
                    s.stake_time = futuretime;
                }); 

                stakedivide(800000000000000,delaytime+5);
            }

            if(gameitr->stake_token>0 && gameitr->stake_token_mirror>0 && gameitr->stake_jackpot_mirror>0)
            {
                for(;playeritr!=players.end();++playeritr)
                {
                    if((playeritr->id>0 && playeritr->id == gameitr->stake_owner) || playeritr->stake_amount==0) continue;

                    auto ratio = double(playeritr->stake_amount)/double(gameitr->stake_token_mirror);
                    auto bonus = gameitr->stake_jackpot_mirror * ratio;
                    players.modify( playeritr,get_self(), [&]( auto& s ) {
                        s.stake_profit += bonus;
                    });
                    if(count>100)
                    {
                        games.modify( gameitr,get_self(), [&]( auto& s ) {
                            s.stake_owner = playeritr->id;
                        });
                        break;
                    }
                    count++;   
                }

                if(playeritr==players.end())
                {
                    games.modify( gameitr,get_self(), [&]( auto& s ) {
                        s.stake_owner = 0;
                        s.stake_token_mirror = 0;
                        s.stake_jackpot_mirror = 0;
                    });
                }else
                {
                    stakedivide(900000000000000,0);
                }
            }
        }
    }

    // 团队利润
    ACTION teambonus(uint64_t bonus_time)
    {
        require_auth(get_self()); 

        auto gameitr = games.begin();
        teamdivide(990000000000000,3600);
        if(gameitr!=games.end() && gameitr->team_jackpot>0)
        {
            auto team_fee = 0UL;
            auto deve_fee = 0UL;
            auto total_fee = gameitr->team_fee;
            auto current_fee = gameitr->team_jackpot;
            if(total_fee>35000000)
            {
                deve_fee = current_fee * 0.1;
                team_fee = current_fee - deve_fee;

            }else
            {
                team_fee = current_fee - deve_fee;
            }

            string remark = "定时提取团队利润";
            remark.append(REMARK);

            if(team_fee>0)
            {
                asset teamfee(team_fee,CORE_TOKEN);
                action(permission_level{get_self(), "active"_n},CORE_ACCOUNT,"transfer"_n,make_tuple(get_self(), TEAM_ACCOUNT, teamfee, remark)).send();
            }
 
            if(deve_fee>0)
            {
                asset devefee(deve_fee,CORE_TOKEN);
                action(permission_level{get_self(), "active"_n},CORE_ACCOUNT,"transfer"_n,make_tuple(get_self(), DEVE_ACCOUNT, devefee, remark)).send();
            }

            games.modify(gameitr, get_self(), [&](auto &s) {
                if(gameitr->team_jackpot>=current_fee)
                {
                    s.team_jackpot -= current_fee;
                }else{
                    s.team_jackpot = 0;
                }
            });
        }
    }

    // 并行控制
    ACTION parallel(uint64_t max_count)
    {
        require_auth(CONF_ACCOUNT); 

        auto gameitr = games.begin();
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );

        if(max_count<gameitr->parallel_count)
        {
            auto decrease = gameitr->parallel_count-max_count;
            auto rcounteritr = counters.rbegin();
            vector<uint64_t> numbers;
            while(rcounteritr!=counters.rend())
            {
                if(numbers.size()>=decrease)
                {
                    break;
                }
                numbers.push_back(rcounteritr->id);
                rcounteritr++;
            }
            for(auto id:numbers)
            {
                auto counteritr = counters.find(id);
                counters.erase(counteritr);
            }
            games.modify(gameitr,get_self(),[&](auto&s){
                s.parallel_count=max_count;
            });
        }else if(max_count>gameitr->parallel_count)
        {
            auto increase = max_count-gameitr->parallel_count;
            for(auto i=0;i<increase;i++)
            {
                counters.emplace(get_self(),[&](auto&s){
                    s.id = gameitr->parallel_count+i+1;
                    s.is_using=0;
                });
            }
            games.modify(gameitr,get_self(),[&](auto&s){
                s.parallel_count=max_count;
            });
        }
        hatch_egg();
    }

    // 修改价格
    ACTION changeprice(name owner,uint64_t length, asset quantity)
    {
        require_auth(owner); 

        auto storeidx = stores.get_index<"bylength"_n>();
        auto storeitr = storeidx.find(store::length_key(owner,length));
        eosio_assert(length>=1 && length<=3,"修改的长度不正确");
        eosio_assert(storeitr!=storeidx.end() && storeitr->owner==owner && storeitr->egg_length == length,"修改的鹅蛋不存在");
        
        storeidx.modify(storeitr,get_self(),[&](auto&s){
            if(storeitr->egg_count==0)
            {
                s.egg_price=0;
            }else
            {
                s.egg_price = quantity.amount;
            }
        });
    }

    // 结算订单
    ACTION drawing(uint64_t id,name owner,uint64_t name_length,uint64_t hatch_number,string hatch_price,uint64_t delay_time,string start_time,string hatch_time,string result_number,uint64_t block_number,string block_hashcode)
    {
        require_auth(DRAW_ACCOUNT); 
        require_recipient(owner);
        require_recipient(LOGS_ACCOUNT);

        auto gameitr = games.begin();
        auto settingitr = settings.begin();
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );

        auto now_time = time_point(microseconds(current_time()));
        auto orderitr = orders.find(id);
        eosio_assert(orderitr!=orders.end(), "订单ID不存在" );
        eosio_assert(orderitr->hatch_status==1, "尚未到达孵化时间" );
        eosio_assert(now_time>=orderitr->hatch_time, "尚未到达孵化时间" );

        auto eggitr = eggs.find(orderitr->name_length);
        eosio_assert(eggitr!=eggs.end(), "孵化定价不存在" );

        // string final_text = "";
        // for (int i = 0; i<block_hashcode.length() ; i++)  
        // {  
        //     if(block_hashcode[i]>='0' && block_hashcode[i]<='9')
        //     {
        //       final_text+=block_hashcode[i];
        //     }
        // }  

        auto final_number = stoull(result_number);//stoull(final_text.substr(final_text.size()-2,2));
        if(result_number.size()>0 && final_number<orderitr->hatch_number)
        {
            // 更新市场
            markets.emplace(get_self(),[&](auto&s){
                s.id = markets.available_primary_key();
                s.owner = orderitr->owner;
                s.count = orderitr->hatch_count;
                s.price = eggitr->sell_price;
                s.length = orderitr->name_length;
            });

            // 更新统计
            games.modify(gameitr,get_self(),[&](auto&s){
                s.total_hatch_count+=orderitr->hatch_count;
                s.total_order_count--;
                s.total_counter_count--;
            });

            // 更新订单
            orders.modify(orderitr,get_self(),[&](auto&s){
                s.hatch_status=2;
                s.result_number = final_number;
                s.result_hashcode = block_hashcode;
            });

            // 更新孵化数量
            eggs.modify(eggitr,get_self(),[&](auto&s){
                s.hatch_count +=orderitr->hatch_count ;
            });

            // 更新店铺
            auto storeidx = stores.get_index<"bylength"_n>();
            auto storeitr = storeidx.find(store::length_key(orderitr->owner,orderitr->name_length));
            if(storeitr!=storeidx.end() && storeitr->owner==orderitr->owner && storeitr->egg_length == orderitr->name_length)
            {
                storeidx.modify(storeitr,get_self(),[&](auto&s){
                    s.egg_count+=orderitr->hatch_count;
                    s.hatch_count+=orderitr->hatch_count;
                    s.queue_count--;
                });
            }

            //更新玩家
            auto playeridx = players.get_index<"byowner"_n>();
            auto playeritr = playeridx.find(orderitr->owner.value);
            eosio_assert(playeritr != playeridx.end(), "下注账号不存在"); 
            playeridx.modify(playeritr,get_self(),[&](auto&s){
                s.hatch_count+=orderitr->hatch_count;
            });

        }else{
            // 更新订单
            orders.modify(orderitr,get_self(),[&](auto&s){
                s.hatch_status=3;
                s.result_number = final_number;
                s.result_hashcode = block_hashcode;
            });

            // 更新统计
            games.modify(gameitr,get_self(),[&](auto&s){
                s.total_order_count--;
                s.total_counter_count--;
            });

            // 更新店铺
            auto storeidx = stores.get_index<"bylength"_n>();
            auto storeitr = storeidx.find(store::length_key(orderitr->owner,orderitr->name_length));
            if(storeitr!=storeidx.end() && storeitr->owner==orderitr->owner && storeitr->egg_length == orderitr->name_length)
            {
                storeidx.modify(storeitr,get_self(),[&](auto&s){
                    s.queue_count--;
                });
            }
        }

        eggs.modify(eggitr,get_self(),[&](auto&s){
            s.queue_count -- ;
        });

        auto counteritr = counters.find(orderitr->count_index);
        if(counteritr!=counters.end())
        {
            counters.modify(counteritr,get_self(),[&](auto&s){
                s.is_using=0;
            });
        }

        // 移除订单
        auto removecount = 0;
        auto removeidx = orders.get_index<"bystatus"_n>();
        auto removeitr = removeidx.lower_bound(2);
        while( removeitr != removeidx.end() && removeitr->hatch_status>=2 && removeitr->id<id) 
        {
            if(removecount>=5)break;
            removeitr = removeidx.erase(removeitr);
            removecount++;
        }

        // 进入窗口
        hatch_egg();

    }

    // 开始孵化
    ACTION hatching(uint64_t id,name owner,uint64_t name_length,uint64_t hatch_number,string hatch_price,uint64_t delay_time,string start_time,string hatch_time,uint64_t block_number)
    {
        require_auth(DRAW_ACCOUNT); 
        require_recipient(owner);
        require_recipient(LOGS_ACCOUNT);
    }

    // 注册账号
    ACTION registry(string payment,string account_name,string account_suffix,string public_key)
    {
        require_auth(DRAW_ACCOUNT);
        reg_name(payment,account_name,account_suffix,public_key);
    }

    // 测试方法
    ACTION test(){

    }

    // 重置窗口
    ACTION resetcounter()
    {
        require_auth(CONF_ACCOUNT); 

        auto gameitr = games.begin();
        auto settingitr = settings.begin();
        eosio_assert(gameitr!=games.end(), "游戏尚未初始化" );
        eosio_assert(settingitr!=settings.end(), "系统尚未初始化" );

        auto counteritr = counters.begin();
        while( counteritr != counters.end() ) 
        {
            counteritr = counters.erase(counteritr);
        }

        for(auto i=0;i< gameitr->parallel_count;i++)
        {
            counters.emplace(get_self(),[&](auto&s){
                s.id = gameitr->parallel_count+i+1;
                s.is_using=0;
            });
        }

        games.modify(gameitr,get_self(),[&](auto&s){
            s.total_counter_count=0;
        });

        auto orderidx = orders.get_index<"bylength"_n>();
        auto orderitr = orderidx.lower_bound(order::length_key(1,1));
        while( orderitr!=orderidx.end() && orderitr->hatch_status==1) 
        {
            orderidx.modify(orderitr,get_self(),[&](auto&s){
                s.hatch_status=0;
                s.count_index = 0;
            });
        }

        hatch_egg();
    }

    // 设置后缀
    ACTION setsuffix(uint64_t set_type,name name_suffix)
    {
        require_auth(CONF_ACCOUNT); 

        eosio_assert(name_suffix.to_string().substr(0,1)=="." && name_suffix.to_string().size()==2, "账号后缀不正确" );

        if(set_type==0)
        {
            auto suffixitr = suffixes.find(name_suffix.value);
            if(suffixitr==suffixes.end())
            {
                suffixes.emplace(get_self(),[&](auto&s){
                    s.symbol = name_suffix;
                });
            }
        }else if (set_type==1)
        {
            auto suffixitr = suffixes.find(name_suffix.value);
            if(suffixitr!=suffixes.end())
            {
                suffixes.erase(suffixitr);
            }
        }
    }

    // 系统配置
    ACTION setglobal(string key,uint64_t value)
    {
        require_auth(CONF_ACCOUNT); 

        auto settingitr = settings.begin();
        settings.modify(settingitr,get_self(),[&](auto&s){
            if(key=="is_buying")
            {
                s.is_buying = value;
            }else if(key=="is_mining")
            {
                s.is_mining = value;
            }else if(key=="is_bidding")
            {
                s.is_bidding = value;
            }else if(key=="is_staking")
            {
                s.is_staking = value;
            }else if(key=="is_hatching")
            {
                s.is_hatching = value;
            }else if(key=="hatch_max")
            {
                s.hatch_max = value;
            }else if(key=="hatch_water")
            {
                s.hatch_water = value;
            }else if(key=="hatch_chance")
            {
                s.hatch_chance = value;
            }else if(key=="stake_time_offset")
            {
                s.stake_time_offset = value;
            }else if(key=="stake_time_redeem")
            {
                s.stake_time_redeem = value;
            }else if(key=="stake_share_ratio")
            {
                s.stake_share_ratio = value;
            }else if(key=="eosio_stake_cpu")
            {
                s.eosio_stake_cpu = value;
            }else if(key=="eosio_stake_net")
            {
                s.eosio_stake_net = value;
            }else if(key=="eosio_stake_ram")
            {
                s.eosio_stake_ram = value;
            }else if(key=="eosio_stake_max")
            {
                s.eosio_stake_max = value;
            }else if(key=="eosio_stake_time")
            {
                s.eosio_stake_time = value;
            }
            
        });
    }

    // 孵化配置
    ACTION sethatch(uint64_t length,string key,uint64_t value)
    {
        require_auth(CONF_ACCOUNT); 

        auto eggitr = eggs.find(length);
        if(eggitr!=eggs.end())
        {
            eggs.modify(eggitr,get_self(),[&](auto&s){
                if(key=="min_price")
                {
                    s.min_price = value;
                }else if(key=="max_price")
                {
                    s.max_price = value;
                }else if(key=="sell_price")
                {
                    s.sell_price = value;
                }else if(key=="pack_price")
                {
                    s.pack_price = value;
                }else if(key=="pack_condition")
                {
                    s.pack_condition = value;
                }else if(key=="pack_is_double")
                {
                    s.pack_is_double = value;
                }else if(key=="delay_time")
                {
                    s.delay_time = value;
                }else if(key=="delay_multiple")
                {
                    s.delay_multiple = value;
                }else if(key=="team_ratio")
                {
                    s.team_ratio = value;
                }else if(key=="proxy_ratio")
                {
                    s.proxy_ratio = value;
                }else if(key=="stake_ratio")
                {
                    s.stake_ratio = value;
                }else if(key=="bidding_ratio")
                {
                    s.bidding_ratio = value;
                }else if(key=="referrer_ratio")
                {
                    s.referrer_ratio = value;
                }
            });
            
        }
    }

    // 创建位数
    ACTION seteeggs(uint64_t length,string suffix)
    {
        require_auth(CONF_ACCOUNT); 

        eggs.emplace(get_self(),[&](auto & s){
            s.id = length;
            s.min_price = 0;
            s.max_price = 0;
            s.name_suffix = name(suffix);

            s.delay_multiple = 12;
            s.sell_price = 7000;
            s.pack_price = 10;
            s.pack_is_double = 1;

            s.team_ratio = 7500;
            s.proxy_ratio = 200;
            s.stake_ratio = 2000;
            s.bidding_ratio = 0;
            s.referrer_ratio = 500;  
        });
    }

    //系统初始化
    ACTION initialize()
    {
        require_auth(CONF_ACCOUNT); 

        // 配置初始化
        auto settingitr = settings.begin();
        if(settingitr==settings.end())
        {
            settingitr = settings.emplace(get_self(),[&](auto & s){
                s.id = 0;
                s.is_buying = 1;              // 允许购买
                s.is_mining = 1;              // 允许挖矿
                s.is_bidding = 0;             // 允许竞拍
                s.is_staking = 1;             // 允许质押
                s.is_hatching = 1;            // 允许孵化
                s.hatch_max = 9500;           // 孵化最大概率95
                s.hatch_water = 0;            // 孵化系统抽水0
                s.hatch_chance = 10000;       // 孵化概率点数100
                s.stake_time_offset = 86400;  // 质押分红间隔
                s.stake_time_redeem = 86400;  // 质押赎回间隔
                s.stake_share_ratio = 500;    // 质押分红比例
                s.eosio_stake_cpu = 2900;     // 抵押CPU
                s.eosio_stake_net = 100;      // 抵押NET
                s.eosio_stake_ram = 3072;     // 抵押RAM
                s.eosio_stake_max = 1600;     // 抵押最大金额
                s.eosio_stake_time = 86400*2; // 质押赎回时间
            });
        }

        // 游戏初始化
        auto parallel = 1;
        auto gameitr = games.begin();
        if(gameitr==games.end())
        {
            games.emplace(get_self(),[&](auto & s){
                s.id = 0;
                s.parallel_count = parallel;
                s.total_drawing_count = 100000000000000;
                s.total_transfer_count = 300000000000000;
                s.total_hatching_count = 500000000000000;
                s.total_identity_count = 700000000000000;
            });
        }

        // 前台初始化
        auto counteritr = counters.begin();
        if(counteritr==counters.end())
        {
          for(auto i=0;i<parallel;i++)
          {
              counters.emplace(get_self(),[&](auto&s){
                  s.id = i+1;
                  s.is_using=0;
              });
          }
        }

        // 账号后缀初始化
        auto suffixitr = suffixes.begin();
        if(suffixitr==suffixes.end())
        {
            suffixes.emplace(get_self(),[&](auto&s){
                s.symbol = name(".c");
            });
        }

        // 孵化初始化
        auto eggitr = eggs.begin();
        if(eggitr==eggs.end())
        {
            for(auto i=1;i<=10;i++)
            {
                eggs.emplace(get_self(),[&](auto & s){
                    s.id = i;
                    s.min_price = 0;
                    s.max_price = 0;
                    s.name_suffix = name(".global");
                    if(i==1){
                        //s.delay_time = 12*60*60;
                        s.pack_price = 16900;
                        s.pack_condition = 2;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==2){
                        //s.delay_time = 10*60*60;
                        s.pack_price = 8500;
                        s.pack_condition = 2;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==3){
                        //s.delay_time = 8*60*60;
                        s.pack_price = 5760;
                        s.pack_condition = 2;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==4){
                        s.delay_multiple = 240;
                        s.sell_price = 237000;
                        s.pack_price = 1770;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==5){
                        s.delay_multiple = 72;
                        s.sell_price = 57000;
                        s.pack_price = 420;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==6){
                        s.delay_multiple = 60;
                        s.sell_price = 47000;
                        s.pack_price = 350;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==7){
                        s.delay_multiple = 48;
                        s.sell_price = 37000;
                        s.pack_price = 280;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;
                    }else if(i==8){
                        s.delay_multiple =  12;
                        s.sell_price = 3700;
                        s.pack_price = 10;
                        s.pack_is_double = 1;
                        
                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;                     
                    }else if(i==9){
                        s.delay_multiple =  12;
                        s.sell_price = 3700;
                        s.pack_price = 10;
                        s.pack_is_double = 1;
                        
                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;    
                    }else if(i==10){
                        s.delay_multiple = 12;
                        s.sell_price = 3700;
                        s.pack_price = 10;
                        s.pack_is_double = 1;

                        s.team_ratio = 7500;
                        s.proxy_ratio = 200;
                        s.stake_ratio = 2000;
                        s.bidding_ratio = 0;
                        s.referrer_ratio = 500;    
                    }
                });
            }
        }

        // 团队自动分红24小时一次
        teamdivide(990000000000000,0);

        // 质押自动分红24小时一次
        stakedivide(800000000000000,0);
    }

    // 清理数据
    ACTION clean(uint64_t type)
    {
        require_auth(CONF_ACCOUNT); 

        if(type==0){
            auto settingitr = settings.begin();
            while( settingitr != settings.end() ) 
            {
                settingitr = settings.erase(settingitr);
            } 

            auto gameitr = games.begin();
            while( gameitr != games.end() ) 
            {
                gameitr = games.erase(gameitr);
            }

            auto eggitr = eggs.begin();
            while( eggitr != eggs.end() ) 
            {
                eggitr = eggs.erase(eggitr);
            }

            auto counteritr = counters.begin();
            while( counteritr != counters.end() ) 
            {
                counteritr = counters.erase(counteritr);
            }
        }
        else if(type==1)//玩家数据
        {
            auto playeritr = players.begin();
            auto playercount = 0;
            while( playeritr != players.end()) 
            {
                if(playercount>=150)break;
                playeritr = players.erase(playeritr);
                playercount++;
            }
        }else if(type==2)//订单数据
        {
            auto orderitr = orders.begin();
            auto ordercount = 0;
            while( orderitr != orders.end()) 
            {
                if(ordercount>=150)break;
                orderitr = orders.erase(orderitr);
                ordercount++;
            }
        }else if(type==3)//市场数据
        {
            auto marketitr = markets.begin();
            auto marketcount = 0;
            while( marketitr != markets.end()) 
            {
                if(marketcount>=150)break;
                marketitr = markets.erase(marketitr);
                marketcount++;
            }
        }else if(type==4)//店铺数据
        {
            auto storeitr = stores.begin();
            auto storecount = 0;
            while( storeitr != stores.end()) 
            {
                if(storecount>=150)break;
                storeitr = stores.erase(storeitr);
                storecount++;
            }
        }else if(type==5)//账号后缀
        {
            auto suffixitr = suffixes.begin();
            auto suffixcount = 0;
            while( suffixitr != suffixes.end()) 
            {
                if(suffixcount>=150)break;
                suffixitr = suffixes.erase(suffixitr);
                suffixcount++;
            }
        }
        
    }

};

#define EOSIO_DISPATCH_CUSTOM( TYPE, MEMBERS ) \
extern "C" { \
   void apply( uint64_t receiver, uint64_t code, uint64_t action ) { \
      if( (code == receiver && action!=name("transfer").value) || ((code==CORE_ACCOUNT.value || code==ISSUE_ACCOUNT.value) && action==name("transfer").value)) { \
         switch( action ) { \
            EOSIO_DISPATCH_HELPER( TYPE, MEMBERS ) \
         } \
      } \
   } \
} \

EOSIO_DISPATCH_CUSTOM( stardustcore, (initialize)(setglobal)(sethatch)(setsuffix)(transfer)(parallel)(changeprice)(resetcounter)(hatching)(drawing)(teambonus)(stakeclaim)(stakebonus)(unstake)(unstakeoff)(registry)(seteeggs)(clean)(test))      


