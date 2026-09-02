-- ============================================================================
-- Shopee Thailand Data Warehouse — 敏感字段加密版
-- 加密算法: AES-256-ECB (确定性加密, 同明文+同密钥→同密文)
-- 密文存储: Base64 编码后存 VARCHAR/MEDIUMTEXT
-- 加密范围: product_id / item_id / product_name / sku / parent_sku
-- STG层保留明文, DWH层仅存密文
-- ============================================================================
-- ⚠️ 执行前必读:
--   1. 替换 PART 0.1 中的 @aes_key 为生产环境 32 字节安全密钥
--   2. 每次会话执行加密/解密前必须先运行 PART 0 (设置模式+密钥+函数)
--   3. 密钥一旦更换, 历史密文将无法解密, 须按密钥轮换流程重新加密
-- ============================================================================


-- ============================================================
-- PART 0: 加密初始化 (每次会话必须最先执行)
-- ============================================================

-- ==================== 0.1 设置加密模式与密钥 ====================
-- AES-256-ECB: 电子密码本模式, 无IV, 确定性输出
-- 为什么不用 CBC: CBC 每次加密需要随机IV, 同明文产生不同密文,
--                 会导致 product_id/item_id 的 JOIN、GROUP BY、主键全部失效
-- ECB 的已知弱点: 相同明文块产生相同密文块, 可能泄露数据模式。
--   缓解: product_id/item_id c
--         product_name 可能重复, 但仅暴露"哪些行商品名相同", 不暴露明文本身。
SET block_encryption_mode = 'aes-256-ecb';

-- ⚠️ 生产环境必须替换为 32 字节随机密钥! 示例密钥仅用于测试。
-- 生成方法: SELECT SHA2(UUID(), 256); 取前32字符, 或使用 KMS 管理
SET @aes_key = 'ThShopeeDW2026SecureKey!@#$%^&*_';  -- 32字节=AES-256, MUST REPLACE IN PRODUCTION

-- ==================== 0.2 创建加密/解密辅助函数 ====================
-- f_enc(plaintext) → Base64密文
-- f_dec(ciphertext) → 明文
-- 封装目的: 避免在每条SQL中硬编码密钥和加密逻辑, 密钥仅存于会话变量
DELIMITER //
DROP FUNCTION IF EXISTS f_enc //
CREATE FUNCTION f_enc(p_text TEXT) RETURNS TEXT
DETERMINISTIC
SQL SECURITY INVOKER
BEGIN
    IF p_text IS NULL THEN
        RETURN NULL;
    END IF;
    -- REPLACE 去掉 TO_BASE64 每76字符插入的换行符, 保证密文连续可比较
    RETURN REPLACE(TO_BASE64(AES_ENCRYPT(p_text, @aes_key)), '\n', '');
END //

DROP FUNCTION IF EXISTS f_dec //
CREATE FUNCTION f_dec(p_cipher TEXT) RETURNS TEXT
DETERMINISTIC
SQL SECURITY INVOKER
BEGIN
    IF p_cipher IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN CAST(AES_DECRYPT(FROM_BASE64(p_cipher), @aes_key) AS CHAR);
END //
DELIMITER ;
-- ==================== 1.1 原始订单表 (59字段) ====================
-- 对应Excel: orignal_order.xlsx
-- 注意: Excel表头第1列 " order_id" 有前导空格, DataGrip导入时手动映射到 order_id
use shpopee_th;
DROP TABLE IF EXISTS stg_orders;
CREATE TABLE stg_orders (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    order_id VARCHAR(50),
    order_status TEXT,
    hot_listing VARCHAR(10),
    order_cancellation_reason TEXT,
    refund_or_return_status TEXT,
    username VARCHAR(100),
    order_date DATETIME,
    payment_time DATETIME,
    payment_channel VARCHAR(100),
    payment_channel_1 VARCHAR(200),
    payment_method VARCHAR(200),
    fee_pct VARCHAR(20),
    shipping_options TEXT,
    shipping_method VARCHAR(50),
    parcel_tracking_number VARCHAR(50),
    expected_delivery_date DATETIME,
    delivery_time DATETIME,
    product_id VARCHAR(50),
    product_name TEXT,
    sku VARCHAR(100),
    variation_name VARCHAR(200),
    original_price DECIMAL(10,2),
    sale_price DECIMAL(10,2),
    quantity INT,
    return_quantity INT,
    final_price DECIMAL(10,2),
    discounts_from_shopee DECIMAL(10,2),
    seller_coupon DECIMAL(10,2),
    coins_cashback_code_paid_by_seller DECIMAL(10,2),
    voucher_amount DECIMAL(10,2),
    discount_code TEXT,
    join_bundle_deal_campaign VARCHAR(10),
    bundle_deal_discount_paid_by_seller DECIMAL(10,2),
    bundle_deal_discount_paid_by_shopee DECIMAL(10,2),
    coin_discount DECIMAL(10,2),
    all_payment_channels_promotions DECIMAL(10,2),
    -- ↓↓↓ v3修正: 列名与Excel完全一致 ↓↓↓
    discount_on_exchanging_old_machines_for_new_ones DECIMAL(10,2),  -- Excel: discount_on_exchanging_old_machines_for_new_ones
    exchanging_new_old_machines_bonus_discount DECIMAL(10,2),         -- Excel: exchanging_new_old_machines_bonus_discount
    commissions DECIMAL(10,2),
    transaction_fee DECIMAL(10,2),
    order_total DECIMAL(10,2),
    shipping_cost_paid_by_the_buyer DECIMAL(10,2),                    -- Excel: shipping_cost_paid_by_the_buyer (带the_)
    approximate_shipping_cost DECIMAL(10,2),
    return_shipping_cost DECIMAL(10,2),
    service_fee DECIMAL(10,2),
    total_amount DECIMAL(10,2),
    approximate_shipping_cost_2 DECIMAL(10,2),
    seller_exchange_bonus DECIMAL(10,2),
    recipient_name VARCHAR(100),
    phone_number VARCHAR(50),
    buyer_note TEXT,
    shipping_address TEXT,
    country VARCHAR(10),
    province VARCHAR(100),
    -- ↓↓↓ v3修正: Excel原始列名为 district_sub-district (连字符) ↓↓↓
    -- DataGrip导入时手动映射: Excel "district_sub-district" → 此列
    district_sub_district VARCHAR(100),
    postal_code VARCHAR(20),
    order_type VARCHAR(50),
    order_completion_time DATETIME,
    notes TEXT,
    load_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_order_id (order_id),
    INDEX idx_order_date (order_date),
    INDEX idx_product_id (product_id),
    INDEX idx_username (username)
) ENGINE=InnoDB;

-- ==================== 1.2 原始产品流量表 (41字段, 月度汇总) ====================
-- 对应Excel: parentskudetail_underscore_headers.xlsx
--
-- ⚠️ DataGrip导入时需要手动映射的列:
--    Excel[35] "Add_to_Cart" (加购数, 整数)      → add_to_cart_count
--    Excel[36] "add_to_cart" (加购转化率, 百分比)  → atc_conv_rate
--    这两列在Excel中名字几乎一样(仅大小写不同), DataGrip无法自动区分!
DROP TABLE IF EXISTS stg_product_traffic;
CREATE TABLE stg_product_traffic (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    y_month varchar(50),
    item_id VARCHAR(50),
    product TEXT,
    current_item_status VARCHAR(50),
    variation_id VARCHAR(50),
    variation_name VARCHAR(200),
    current_variation_status VARCHAR(50),
    sku VARCHAR(100),
    parent_sku VARCHAR(100),
    sales_placed_order VARCHAR(50),
    sales_confirmed_order VARCHAR(50),
    product_impression BIGINT,
    product_clicks BIGINT,
    ctr VARCHAR(20),
    conversion_rate VARCHAR(20),
    order_conv_rate_confirmed VARCHAR(20),
    conversions INT,
    confirmed_order INT,
    units_placed_order INT,
    units_confirmed_order INT,
    buyers_placed_order INT,
    buyers_confirmed_order INT,
    -- ↓↓↓ v3修正: 列名与Excel完全一致 ↓↓↓
    conversion_rate_placed VARCHAR(20),           -- Excel: Conversion_Rate_Placed
    conversion_rate_confirmed VARCHAR(20),         -- Excel: Conversion_Rate_Confirmed
    sales_per_order_placed VARCHAR(50),
    sales_per_order_confirmed VARCHAR(50),
    impressions BIGINT,
    clicks BIGINT,
    visitors INT,
    page_views INT,
    bounce_visitors INT,
    bounce_rate VARCHAR(20),
    search_clicks INT,
    likes INT,
    atc_visitors INT,
    -- ↓↓↓ v3修正: 拆分为两个不同列名, 避免DataGrip映射冲突 ↓↓↓
    add_to_cart_count INT,                         -- Excel[35]: Add_to_Cart (加购数, 如6894)
    atc_conv_rate VARCHAR(20),                     -- Excel[36]: add_to_cart (加购转化率, 如"23.23%")
    repeat_order_rate_placed VARCHAR(20),
    repeat_order_rate_confirmed VARCHAR(20),
    avg_days_to_repeat_placed INT,
    avg_days_to_repeat_confirmed INT,
    load_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_item_id (item_id),
    INDEX idx_y_month (y_month)
) ENGINE=InnoDB;

-- ============================================================
-- PART 2: 分析表建表 (DWH层)
-- ============================================================
-- ============================================================
-- 字段类型变更说明:
--   product_id/item_id: VARCHAR(50) → VARCHAR(255)
--     (AES-256-ECB 输出为16字节倍数, Base64后约为原长1.35倍,
--      50字符输入→最大88字符Base64, VARCHAR(255)留足余量)
--   product_name: TEXT → MEDIUMTEXT
--     (Base64膨胀约33%, 长商品名可能超出TEXT的65535字节)
--   sku/parent_sku: VARCHAR(100) → VARCHAR(255)
--   category/price_band/abc_class: 不加密, 类型不变 (派生指标, 非敏感)

-- ==================== 2.1 订单分析表 ====================
DROP TABLE IF EXISTS dwh_orders;
CREATE TABLE dwh_orders (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    order_id VARCHAR(50),
    username VARCHAR(100),
    status_en VARCHAR(20),
    is_completed TINYINT,
    order_date DATETIME,
    payment_time DATETIME,
    payment_channel_en VARCHAR(50),
    product_id VARCHAR(50),
    product_name TEXT,
    category VARCHAR(50),
    sku VARCHAR(100),
    variation_name VARCHAR(200),
    original_price DECIMAL(10,2),
    sale_price DECIMAL(10,2),
    quantity INT,
    final_price DECIMAL(10,2),
    price_band VARCHAR(30),
    has_seller_coupon TINYINT,
    has_voucher TINYINT,
    has_shopee_discount TINYINT,
    has_bundle_deal TINYINT,
    has_any_discount TINYINT,
    seller_coupon_amount DECIMAL(10,2),
    voucher_amount DECIMAL(10,2),
    shopee_discount_amount DECIMAL(10,2),
    commissions DECIMAL(10,2),
    shipping_cost DECIMAL(10,2),
    total_amount DECIMAL(10,2),
    province VARCHAR(100),
    province_en VARCHAR(100),
    district VARCHAR(100),
    country VARCHAR(10),
    order_month VARCHAR(7),
    order_hour INT,
    order_weekday VARCHAR(10),
    is_weekend TINYINT,
    order_completion_time DATETIME,
    cancel_reason TEXT,
    etl_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_order_id (order_id),
    INDEX idx_username (username),
    INDEX idx_product_id (product_id),
    INDEX idx_order_date (order_date),
    INDEX idx_status (status_en),
    INDEX idx_province (province),
    INDEX idx_category (category)
) ENGINE=InnoDB;

-- ==================== 2.2 产品分析表 (聚合) ====================
DROP TABLE IF EXISTS dwh_products;
CREATE TABLE dwh_products (
    product_id VARCHAR(50) PRIMARY KEY,
    product_name TEXT,
    category VARCHAR(50),
    parent_sku VARCHAR(100),
    price_band VARCHAR(30),
    total_revenue DECIMAL(12,2) DEFAULT 0,               -- 总销售额(从订单表聚合)
    total_orders INT DEFAULT 0,                           -- 总订单数
    total_units INT DEFAULT 0,                            -- 总销售件数
    total_buyers INT DEFAULT 0,                           -- 总买家数
    abc_class CHAR(1),
    total_impressions BIGINT DEFAULT 0,                   -- 注意: 是 impressions (复数)
    total_clicks BIGINT DEFAULT 0,
    total_visitors INT DEFAULT 0,
    total_page_views INT DEFAULT 0,
    total_add_to_cart INT DEFAULT 0,
    avg_ctr DECIMAL(5,2),
    avg_cvr DECIMAL(5,2),
    avg_bounce_rate DECIMAL(5,2),
    avg_repeat_rate DECIMAL(5,2),
    total_likes INT DEFAULT 0,
    etl_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_abc (abc_class)
) ENGINE=InnoDB;

-- ==================== 2.3 产品月度流量表 ====================
DROP TABLE IF EXISTS dwh_product_traffic;
CREATE TABLE dwh_product_traffic (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    y_month date,
    item_id VARCHAR(50),
    product_name TEXT,
    category VARCHAR(50),
    sales_placed DECIMAL(12,2),
    sales_confirmed DECIMAL(12,2),
    impressions BIGINT,
    clicks BIGINT,
    ctr DECIMAL(5,2),
    visitors INT,
    page_views INT,
    add_to_cart INT,
    atc_conv_rate DECIMAL(5,2),
    conversions INT,
    confirmed_order INT,
    units_placed INT,
    buyers_placed INT,
    bounce_rate DECIMAL(5,2),
    repeat_rate DECIMAL(5,2),
    likes INT,
    search_clicks INT,
    sales_per_order DECIMAL(10,2),
    etl_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_item_month (item_id, y_month),
    INDEX idx_year_month (y_month)
) ENGINE=InnoDB;
-- ============================================================
-- PART 3: STG层数据质量清洗
-- 在DataGrip导入后、ETL入DWH前执行
-- ============================================================

-- ==================== 3.1 订单表去重 ====================
DELETE FROM stg_orders
WHERE id IN (
    SELECT tmp.id FROM (
        SELECT
            id,
            ROW_NUMBER() OVER(PARTITION BY order_id, product_id, sku ORDER BY id DESC) rn
        FROM stg_orders
    ) tmp
    WHERE tmp.rn > 1
);

-- ==================== 3.2 订单表空字符串→NULL + 去首尾空格 ====================
-- DataGrip导入Excel时，空白单元格会变成''而非NULL，需统一处理
UPDATE stg_orders
SET
    order_status = NULLIF(TRIM(order_status), ''),
    order_cancellation_reason = NULLIF(TRIM(order_cancellation_reason), ''),
    refund_or_return_status = NULLIF(TRIM(refund_or_return_status), ''),
    username = NULLIF(TRIM(username), ''),
    payment_channel = NULLIF(TRIM(payment_channel), ''),
    payment_channel_1 = NULLIF(TRIM(payment_channel_1), ''),
    payment_method = NULLIF(TRIM(payment_method), ''),
    shipping_options = NULLIF(TRIM(shipping_options), ''),
    shipping_method = NULLIF(TRIM(shipping_method), ''),
    product_id = NULLIF(TRIM(product_id), ''),
    product_name = NULLIF(TRIM(product_name), ''),
    sku = NULLIF(TRIM(sku), ''),
    variation_name = NULLIF(TRIM(variation_name), ''),
    discount_code = NULLIF(TRIM(discount_code), ''),
    join_bundle_deal_campaign = NULLIF(TRIM(join_bundle_deal_campaign), ''),
    recipient_name = NULLIF(TRIM(recipient_name), ''),
    phone_number = NULLIF(TRIM(phone_number), ''),
    buyer_note = NULLIF(TRIM(buyer_note), ''),
    shipping_address = NULLIF(TRIM(shipping_address), ''),
    province = NULLIF(TRIM(province), ''),
    district_sub_district = NULLIF(TRIM(district_sub_district), ''),
    postal_code = NULLIF(TRIM(postal_code), ''),
    order_type = NULLIF(TRIM(order_type), ''),
    notes = NULLIF(TRIM(notes), '')
WHERE
    TRIM(order_status) = ''
    OR TRIM(order_cancellation_reason) = ''
    OR TRIM(refund_or_return_status) = ''
    OR TRIM(username) = ''
    OR TRIM(payment_channel) = ''
    OR TRIM(payment_channel_1) = ''
    OR TRIM(payment_method) = ''
    OR TRIM(shipping_options) = ''
    OR TRIM(shipping_method) = ''
    OR TRIM(product_id) = ''
    OR TRIM(product_name) = ''
    OR TRIM(sku) = ''
    OR TRIM(variation_name) = ''
    OR TRIM(discount_code) = ''
    OR TRIM(join_bundle_deal_campaign) = ''
    OR TRIM(recipient_name) = ''
    OR TRIM(phone_number) = ''
    OR TRIM(buyer_note) = ''
    OR TRIM(shipping_address) = ''
    OR TRIM(province) = ''
    OR TRIM(district_sub_district) = ''
    OR TRIM(postal_code) = ''
    OR TRIM(order_type) = ''
    OR TRIM(notes) = ''
LIMIT 1000;
 -- 空值数量统计
SELECT COUNT(*)
FROM stg_orders
WHERE
    TRIM(order_status) = ''
    OR TRIM(order_cancellation_reason) = ''
    OR TRIM(refund_or_return_status) = ''
    OR TRIM(username) = ''
    OR TRIM(payment_channel) = ''
    OR TRIM(payment_channel_1) = ''
    OR TRIM(payment_method) = ''
    OR TRIM(shipping_options) = ''
    OR TRIM(shipping_method) = ''
    OR TRIM(product_id) = ''
    OR TRIM(product_name) = ''
    OR TRIM(sku) = ''
    OR TRIM(variation_name) = ''
    OR TRIM(discount_code) = ''
    OR TRIM(join_bundle_deal_campaign) = ''
    OR TRIM(recipient_name) = ''
    OR TRIM(phone_number) = ''
    OR TRIM(buyer_note) = ''
    OR TRIM(shipping_address) = ''
    OR TRIM(province) = ''
    OR TRIM(district_sub_district) = ''
    OR TRIM(postal_code) = ''
    OR TRIM(order_type) = ''
    OR TRIM(notes) = '';


-- ==================== 3.3 订单表无效日期→NULL ====================
-- Excel中空日期可能变成'0000-00-00'或空字符串，需清理
UPDATE stg_orders
SET
    order_status = NULLIF(TRIM(order_status), ''),
    order_cancellation_reason = NULLIF(TRIM(order_cancellation_reason), ''),
    refund_or_return_status = NULLIF(TRIM(refund_or_return_status), ''),
    username = NULLIF(TRIM(username), ''),
    payment_channel = NULLIF(TRIM(payment_channel), ''),
    payment_channel_1 = NULLIF(TRIM(payment_channel_1), ''),
    payment_method = NULLIF(TRIM(payment_method), ''),
    shipping_options = NULLIF(TRIM(shipping_options), ''),
    shipping_method = NULLIF(TRIM(shipping_method), ''),
    product_id = NULLIF(TRIM(product_id), ''),
    product_name = NULLIF(TRIM(product_name), ''),
    sku = NULLIF(TRIM(sku), ''),
    variation_name = NULLIF(TRIM(variation_name), ''),
    discount_code = NULLIF(TRIM(discount_code), ''),
    join_bundle_deal_campaign = NULLIF(TRIM(join_bundle_deal_campaign), ''),
    recipient_name = NULLIF(TRIM(recipient_name), ''),
    phone_number = NULLIF(TRIM(phone_number), ''),
    buyer_note = NULLIF(TRIM(buyer_note), ''),
    shipping_address = NULLIF(TRIM(shipping_address), ''),
    province = NULLIF(TRIM(province), ''),
    district_sub_district = NULLIF(TRIM(district_sub_district), ''),
    postal_code = NULLIF(TRIM(postal_code), ''),
    order_type = NULLIF(TRIM(order_type), ''),
    notes = NULLIF(TRIM(notes), ''),
    order_date = NULLIF(TRIM(order_date), ''),
    payment_time = NULLIF(TRIM(payment_time), ''),
    order_completion_time = IF(CAST(order_completion_time AS CHAR) = '0000-00-00 00:00:00', NULL, order_completion_time)
WHERE
    TRIM(order_status) = ''
    OR TRIM(order_cancellation_reason) = ''
    OR TRIM(refund_or_return_status) = ''
    OR TRIM(username) = ''
    OR TRIM(payment_channel) = ''
    OR TRIM(payment_channel_1) = ''
    OR TRIM(payment_method) = ''
    OR TRIM(shipping_options) = ''
    OR TRIM(shipping_method) = ''
    OR TRIM(product_id) = ''
    OR TRIM(product_name) = ''
    OR TRIM(sku) = ''
    OR TRIM(variation_name) = ''
    OR TRIM(discount_code) = ''
    OR TRIM(join_bundle_deal_campaign) = ''
    OR TRIM(recipient_name) = ''
    OR TRIM(phone_number) = ''
    OR TRIM(buyer_note) = ''
    OR TRIM(shipping_address) = ''
    OR TRIM(province) = ''
    OR TRIM(district_sub_district) = ''
    OR TRIM(postal_code) = ''
    OR TRIM(order_type) = ''
    OR TRIM(notes) = ''
    OR TRIM(order_date) = ''
    OR TRIM(payment_time) = ''
    OR CAST(order_completion_time AS CHAR) = '0000-00-00 00:00:00'
LIMIT 1000;
 -- 统计脏时间数据条数
SELECT COUNT(*) bad_cnt
FROM stg_orders
WHERE CAST(order_completion_time AS CHAR) = '0000-00-00 00:00:00';

-- ==================== 3.4 订单表异常值处理 ====================
-- 价格为负或为0的记录标记为NULL（不删除，保留审计痕迹）
UPDATE stg_orders SET original_price = NULL WHERE original_price <= 0;
UPDATE stg_orders SET sale_price = NULL WHERE sale_price <= 0;
UPDATE stg_orders SET quantity = NULL WHERE quantity <= 0;
UPDATE stg_orders SET final_price = NULL WHERE final_price < 0;

-- 折扣金额为负的转为正数（可能是导入符号问题）
UPDATE stg_orders SET seller_coupon = ABS(seller_coupon) WHERE seller_coupon < 0;
UPDATE stg_orders SET voucher_amount = ABS(voucher_amount) WHERE voucher_amount < 0;
UPDATE stg_orders SET discounts_from_shopee = ABS(discounts_from_shopee) WHERE discounts_from_shopee < 0;

-- ==================== 3.5 产品流量表去重 ====================
-- 按月份+商品ID去重，保留最新一条
delete from stg_orders
where id in
(
    select tmp.id from
                      (
                          select id,
                                 row_number() over (partition by y_month,item_id,id order by id desc) rn
                          from stg_product_traffic
                      )tmp
    where tmp.rn>1
    );
-- ==================== 3.5b y_month 日期格式标准化 ====================
-- v6新增: DataGrip导入Excel datetime时, y_month可能变成各种文本格式
-- 这里统一转换成 YYYY-MM-DD 格式, 保证后续 DATE_FORMAT 能正确处理
--
-- 可能的格式:
--   "2026-01-01 00:00:00" → 取前10位即可
--   "2026/1" 或 "2026/01"  → 补日 + 转斜杠为横杠
--   "2026-01"              → 补 -01
--   "2026/1/1"             → STR_TO_DATE
--   "2026-01-01"           → 已标准, 不动
--
-- 策略: 用多条件UPDATE分别处理各种格式
-- 注: 每条UPDATE的WHERE都是具体格式匹配, 非恒真

-- 格式1: "2026-01-01 00:00:00" 或 "2026-01-01" (已含横杠, 长度>=10)
UPDATE stg_product_traffic
SET y_month = LEFT(TRIM(y_month), 10)
WHERE y_month IS NOT NULL
  AND TRIM(y_month) LIKE '____-__-__%';

-- 格式2: "2026/1" 或 "2026/01" (斜杠分隔, 只有年月, 长度6-7)
UPDATE stg_product_traffic
SET y_month = CONCAT(
    SUBSTRING_INDEX(TRIM(y_month), '/', 1), '-',
    LPAD(SUBSTRING_INDEX(TRIM(y_month), '/', -1), 2, '0'),
    '-01'
)
WHERE y_month IS NOT NULL
  AND TRIM(y_month) LIKE '____/_%'
  AND TRIM(y_month) NOT LIKE '%/%/%';

-- 格式3: "2026/1/1" 或 "2026/01/01" (斜杠分隔, 完整日期)
UPDATE stg_product_traffic
SET y_month = DATE_FORMAT(STR_TO_DATE(TRIM(y_month), '%Y/%m/%d'), '%Y-%m-%d')
WHERE y_month IS NOT NULL
  AND TRIM(y_month) LIKE '%/%/%';

-- 格式4: "2026-01" (横杠分隔, 只有年月, 长度7)
UPDATE stg_product_traffic
SET y_month = CONCAT(TRIM(y_month), '-01')
WHERE y_month IS NOT NULL
  AND TRIM(y_month) LIKE '____-__'
  AND LENGTH(TRIM(y_month)) = 7;
-- ==================== 3.6 产品流量表空字符串→NULL + 去首尾空格 ====================
update stg_product_traffic
set
    item_id=nullif(trim(item_id),''),
    product=nullif(trim(product),''),
    current_item_status=nullif(trim(current_item_status),''),
    variation_id=nullif(trim(variation_id),''),
    variation_name=nullif(trim(variation_name),''),
    current_variation_status=nullif(trim(current_variation_status),''),
    sku=nullif(trim(sku),''),
    parent_sku=nullif(trim(parent_sku),'')
where
    trim(item_id) =''
    or trim(product)=''
or trim(current_item_status)=''
or trim(variation_id)=''
or trim(variation_name)=''
or trim(current_variation_status)=''
or trim(sku)=''
or trim(parent_sku)=''
limit 1000;
 -- 统计字符
 select count(*)
 from stg_product_traffic
where
    trim(item_id) =''
    or trim(product)=''
or trim(current_item_status)=''
or trim(variation_id)=''
or trim(variation_name)=''
or trim(current_variation_status)=''
or trim(sku)=''
or trim(parent_sku)='';


-- ==================== 3.7 产品流量表数字格式清洗 ====================
-- Shopee导出的数字带逗号(如"1,234.56")，百分比带%(如"12.5%")
-- 在STG层统一清洗，ETL层只需CAST即可

-- 3.7a 清洗逗号分隔的金额字段 (去掉逗号, 空值→NULL)
update stg_product_traffic
set sales_placed_order=nullif(trim(replace(sales_placed_order,',',' ')),'')
where sales_placed_order is not null;

update stg_product_traffic
set sales_confirmed_order=nullif(trim(replace(sales_confirmed_order,',',' ')),'')
where sales_confirmed_order is not null;
UPDATE stg_product_traffic
SET sales_per_order_placed = NULLIF(TRIM(REPLACE(sales_per_order_placed, ',', '')), '')
WHERE sales_per_order_placed IS NOT NULL;

UPDATE stg_product_traffic
SET sales_per_order_confirmed = NULLIF(TRIM(REPLACE(sales_per_order_confirmed, ',', '')), '')
WHERE sales_per_order_confirmed IS NOT NULL;

-- 3.7b 清洗百分号字段 (去掉%, 空值→NULL)
UPDATE stg_product_traffic SET ctr = NULLIF(TRIM(REPLACE(ctr, '%', '')), '') WHERE ctr IS NOT NULL;
UPDATE stg_product_traffic SET conversion_rate = NULLIF(TRIM(REPLACE(conversion_rate, '%', '')), '') WHERE conversion_rate IS NOT NULL;
UPDATE stg_product_traffic SET order_conv_rate_confirmed = NULLIF(TRIM(REPLACE(order_conv_rate_confirmed, '%', '')), '') WHERE order_conv_rate_confirmed IS NOT NULL;
UPDATE stg_product_traffic SET conversion_rate_placed = NULLIF(TRIM(REPLACE(conversion_rate_placed, '%', '')), '') WHERE conversion_rate_placed IS NOT NULL;
UPDATE stg_product_traffic SET conversion_rate_confirmed = NULLIF(TRIM(REPLACE(conversion_rate_confirmed, '%', '')), '') WHERE conversion_rate_confirmed IS NOT NULL;
UPDATE stg_product_traffic SET bounce_rate = NULLIF(TRIM(REPLACE(bounce_rate, '%', '')), '') WHERE bounce_rate IS NOT NULL;
UPDATE stg_product_traffic SET atc_conv_rate = NULLIF(TRIM(REPLACE(atc_conv_rate, '%', '')), '') WHERE atc_conv_rate IS NOT NULL;
UPDATE stg_product_traffic SET repeat_order_rate_placed = NULLIF(TRIM(REPLACE(repeat_order_rate_placed, '%', '')), '') WHERE repeat_order_rate_placed IS NOT NULL;
UPDATE stg_product_traffic SET repeat_order_rate_confirmed = NULLIF(TRIM(REPLACE(repeat_order_rate_confirmed, '%', '')), '') WHERE repeat_order_rate_confirmed IS NOT NULL;

-- 3.7c 清洗后空字符串→NULL (处理原本就是空字符串的字段)
UPDATE stg_product_traffic SET sales_placed_order = NULL WHERE sales_placed_order = '';
UPDATE stg_product_traffic SET sales_confirmed_order = NULL WHERE sales_confirmed_order = '';
UPDATE stg_product_traffic SET sales_per_order_placed = NULL WHERE sales_per_order_placed = '';
UPDATE stg_product_traffic SET sales_per_order_confirmed = NULL WHERE sales_per_order_confirmed = '';
UPDATE stg_product_traffic SET ctr = NULL WHERE ctr = '';
UPDATE stg_product_traffic SET conversion_rate = NULL WHERE conversion_rate = '';
UPDATE stg_product_traffic SET bounce_rate = NULL WHERE bounce_rate = '';
UPDATE stg_product_traffic SET repeat_order_rate_placed = NULL WHERE repeat_order_rate_placed = '';

-- ==================== 3.8 数据质量校验 ====================
-- 清洗完成后执行以下校验查询，确认数据质量
SELECT 'stg_orders总行数' AS metric, COUNT(*) AS value FROM stg_orders
UNION ALL SELECT 'stg_orders去重后唯一订单数', COUNT(DISTINCT order_id) FROM stg_orders
UNION ALL SELECT 'stg_orders空order_date行数', COUNT(*) FROM stg_orders WHERE order_date IS NULL
UNION ALL SELECT 'stg_orders空product_id行数', COUNT(*) FROM stg_orders WHERE product_id IS NULL
UNION ALL SELECT 'stg_product_traffic总行数', COUNT(*) FROM stg_product_traffic
UNION ALL SELECT 'stg_product_traffic去重后行数', COUNT(DISTINCT CONCAT(y_month, item_id)) FROM stg_product_traffic
UNION ALL SELECT 'stg_product_traffic空item_id行数', COUNT(*) FROM stg_product_traffic WHERE item_id IS NULL;



UPDATE stg_orders
SET order_date = STR_TO_DATE(order_date, '%Y %m %d %H:%i')
WHERE order_date LIKE '% % % %:%';
UPDATE stg_orders
SET payment_time = STR_TO_DATE(payment_time, '%Y %m %d %H:%i')
WHERE payment_time LIKE '% % % %:%';
UPDATE stg_orders
SET expected_delivery_date = STR_TO_DATE(expected_delivery_date, '%Y %m %d %H:%i')
WHERE expected_delivery_date LIKE '% % % %:%';
UPDATE stg_orders
SET delivery_time = STR_TO_DATE(delivery_time, '%Y %m %d %H:%i')
WHERE delivery_time LIKE '% % % %:%';
UPDATE stg_orders
SET order_completion_time = STR_TO_DATE(order_completion_time, '%Y %m %d %H:%i')
WHERE order_completion_time LIKE '% % % %:%';

-- ============================================================
-- PART 4: ETL清洗入DWH层
--
-- ⚠️ 执行顺序 (必须严格按此顺序):
--   4.1 → 4.2 → 4.3 Step1 → 4.3 Step2 → 4.3 Step3 → 4.3 Step4
--
-- ⚠️ total_revenue 在 4.3 Step2 中通过 UPDATE 从 dwh_orders 聚合
--    如果 dwh_orders 为空(Part 4.1没跑), total_revenue 必然为NULL!
-- ============================================================
--
-- ⚠️ 加密原则:
--   1. STG层明文 → ETL时调用 f_enc() → DWH层密文
--   2. category/price_band/abc_class 等派生指标用明文计算后再加密关联键
--   3. product_id/item_id 用同一密钥加密, 保证跨表可JOIN
-- ============================================================

-- ==================== 4.1 订单数据入DWH (加密版) ====================
-- ⚠️ 必须先执行这一步! dwh_orders 是后续 4.3 Step2 的数据源
-- 加密字段: product_id, product_name, sku
-- 明文计算: category (依赖 product_name LIKE), price_band (依赖 sale_price)

INSERT INTO dwh_orders (
    order_id, username, status_en, is_completed,
    order_date, payment_time, payment_channel_en,
    product_id, product_name, category, sku, variation_name,
    original_price, sale_price, quantity, final_price, price_band,
    has_seller_coupon, has_voucher, has_shopee_discount,
    has_bundle_deal, has_any_discount,
    seller_coupon_amount, voucher_amount, shopee_discount_amount,
    commissions, shipping_cost, total_amount,
    province, district, country,
    order_month, order_hour, order_weekday, is_weekend,
    order_completion_time, cancel_reason
)
SELECT
    o.order_id,
    o.username,
    CASE
        WHEN o.order_status LIKE '%สำเร็จแล้ว%' AND o.order_status NOT LIKE '%จัดส่ง%' THEN 'Completed'
        WHEN o.order_status LIKE '%จัดส่งสำเร็จ%' THEN 'Delivered'
        WHEN o.order_status LIKE '%ได้รับสินค้า%' THEN 'Received'
        WHEN o.order_status LIKE '%ยกเลิก%' THEN 'Cancelled'
        ELSE 'Other'
    END AS status_en,
    CASE
        WHEN o.order_status LIKE '%สำเร็จแล้ว%'
          OR o.order_status LIKE '%จัดส่งสำเร็จ%'
          OR o.order_status LIKE '%ได้รับสินค้า%' THEN 1
        ELSE 0
    END AS is_completed,
    o.order_date,
    o.payment_time,
    CASE
        WHEN o.payment_channel = 'SPayLater' THEN 'SPayLater'
        WHEN o.payment_channel = 'เก็บเงินปลายทาง' THEN 'COD'
        WHEN o.payment_channel = 'QR พร้อมเพย์' THEN 'QR PromptPay'
        WHEN o.payment_channel = 'ShopeePay - ตัดบัญชีธนาคาร' THEN 'ShopeePay (Bank)'
        WHEN o.payment_channel = 'Mobile Banking' THEN 'Mobile Banking'
        WHEN o.payment_channel = 'บัตรเครดิต/บัตรเดบิต' THEN 'Credit/Debit Card'
        WHEN o.payment_channel = 'ยอดเงิน ShopeePay' THEN 'ShopeePay Balance'
        WHEN o.payment_channel = 'Google Pay' THEN 'Google Pay'
        ELSE o.payment_channel
    END AS payment_channel_en,
        -- ★ 加密: product_id (确定性加密, 后续可与 dwh_products.product_id JOIN)
    f_enc(o.product_id) AS product_id,
    -- ★ 加密: product_name
    f_enc(o.product_name) AS product_name,
    -- ★ 明文: category 必须用明文 o.product_name 做 LIKE 匹配后再入库
    --   (密文无法做 LIKE 模式匹配, 所以在同一条INSERT内先算后加密)
    CASE
        WHEN o.product_name LIKE '%tote%' OR o.product_name LIKE '%โท้ท%' THEN 'Tote Bag'
        WHEN o.product_name LIKE '%bucket%' OR o.product_name LIKE '%ทรงถัง%' THEN 'Bucket Bag'
        WHEN o.product_name LIKE '%hobo%' THEN 'Hobo Bag'
        WHEN o.product_name LIKE '%croissant%' OR o.product_name LIKE '%ครัวซอง%' THEN 'Croissant Bag'
        WHEN o.product_name LIKE '%mini%' THEN 'Mini Bag'
        WHEN o.product_name LIKE '%crossbody%' OR o.product_name LIKE '%ครอสบอดี้%' THEN 'Crossbody Bag'
        WHEN o.product_name LIKE '%shoulder%' OR o.product_name LIKE '%สะพายไหล่%'
             OR o.product_name LIKE '%สะพายข้าง%' THEN 'Shoulder Bag'
        WHEN o.product_name LIKE '%กระเป๋าถือ%' THEN 'Handbag'
        WHEN o.product_name LIKE '%strap%' OR o.product_name LIKE '%สายสะพาย%' THEN 'Accessory (Strap)'
        ELSE 'Other Bag'
    END AS category,
     -- ★ 加密: sku
    f_enc(o.sku) AS sku,
    o.variation_name,
    o.original_price,
    o.sale_price,
    o.quantity,
    o.final_price,
    -- ★ 明文: price_band 依赖明文 sale_price, 不涉及敏感字段
    CASE
        WHEN o.sale_price < 200 THEN 'Budget (<200 THB)'
        WHEN o.sale_price BETWEEN 200 AND 399 THEN 'Low (200-399 THB)'
        WHEN o.sale_price BETWEEN 400 AND 599 THEN 'Mid (400-599 THB)'
        WHEN o.sale_price BETWEEN 600 AND 999 THEN 'High (600-999 THB)'
        WHEN o.sale_price >= 1000 THEN 'Premium (1000+ THB)'
        ELSE 'Unknown'
    END AS price_band,
    CASE WHEN IFNULL(o.seller_coupon, 0) > 0 THEN 1 ELSE 0 END,
    CASE WHEN IFNULL(o.voucher_amount, 0) > 0 THEN 1 ELSE 0 END,
    CASE WHEN IFNULL(o.discounts_from_shopee, 0) > 0 THEN 1 ELSE 0 END,
    CASE WHEN o.join_bundle_deal_campaign = 'Y' THEN 1 ELSE 0 END,
    CASE WHEN IFNULL(o.seller_coupon, 0) > 0
          OR IFNULL(o.voucher_amount, 0) > 0
          OR IFNULL(o.discounts_from_shopee, 0) > 0
          OR o.join_bundle_deal_campaign = 'Y' THEN 1 ELSE 0 END,
    IFNULL(o.seller_coupon, 0),
    IFNULL(o.voucher_amount, 0),
    IFNULL(o.discounts_from_shopee, 0),
    IFNULL(o.commissions, 0),
    -- v3修正: 使用与Excel一致的列名
    IFNULL(o.shipping_cost_paid_by_the_buyer, 0),
    IFNULL(o.total_amount, 0),
    o.province,
    o.district_sub_district,
    o.country,
    DATE_FORMAT(o.order_date, '%Y-%m'),
    HOUR(o.order_date),
    DAYNAME(o.order_date),
    CASE WHEN DAYOFWEEK(o.order_date) IN (1, 7) THEN 1 ELSE 0 END,
    o.order_completion_time,
    o.order_cancellation_reason
FROM stg_orders o
WHERE o.order_id IS NOT NULL;

-- ==================== 4.2 产品月度流量入DWH ====================
-- v3修正: 使用与Excel/create table一致的列名
-- 从 stg_product_traffic 聚合到 dwh_product_traffic, 按 (y_month, item_id) 分组
-- 加密字段: item_id, product_name
-- 明文计算: category (依赖明文 product 字段做 LIKE)
-- 注意: stg 表字段名为 product, dwh 表字段名为 product_name
ALTER TABLE dwh_product_traffic MODIFY COLUMN y_month VARCHAR(7) NOT NULL;
ALTER TABLE dwh_product_traffic
  MODIFY y_month VARCHAR(10) NOT NULL,
  MODIFY item_id VARCHAR(255),
  MODIFY product_name MEDIUMTEXT;

INSERT INTO dwh_product_traffic (
    y_month, item_id, product_name, category,
    sales_placed, sales_confirmed,
    impressions, clicks, ctr, visitors, page_views,
    add_to_cart, atc_conv_rate, conversions, confirmed_order,
    units_placed, buyers_placed, bounce_rate, repeat_rate, likes,
    search_clicks, sales_per_order
)
SELECT
    LEFT(stg.y_month, 10) AS y_month,
    f_enc(stg.item_id) AS item_id,
    f_enc(MAX(stg.product)) AS product_name,
    CASE
        WHEN MAX(stg.product) LIKE '%tote%' OR MAX(stg.product) LIKE '%โท้ท%' THEN 'Tote Bag'
        WHEN MAX(stg.product) LIKE '%bucket%' OR MAX(stg.product) LIKE '%ทรงถัง%' THEN 'Bucket Bag'
        WHEN MAX(stg.product) LIKE '%hobo%' THEN 'Hobo Bag'
        WHEN MAX(stg.product) LIKE '%croissant%' OR MAX(stg.product) LIKE '%ครัวซอง%' THEN 'Croissant Bag'
        WHEN MAX(stg.product) LIKE '%mini%' THEN 'Mini Bag'
        WHEN MAX(stg.product) LIKE '%crossbody%' OR MAX(stg.product) LIKE '%ครอสบอดี้%' THEN 'Crossbody Bag'
        WHEN MAX(stg.product) LIKE '%shoulder%' OR MAX(stg.product) LIKE '%สะพายไหล่%'
             OR MAX(stg.product) LIKE '%สะพายข้าง%' THEN 'Shoulder Bag'
        WHEN MAX(stg.product) LIKE '%กระเป๋าถือ%' THEN 'Handbag'
        WHEN MAX(stg.product) LIKE '%strap%' OR MAX(stg.product) LIKE '%สายสะพาย%' THEN 'Accessory (Strap)'
        ELSE 'Other Bag'
    END AS category,
    SUM(CAST(stg.sales_placed_order AS DECIMAL(12,2))),
    SUM(CAST(stg.sales_confirmed_order AS DECIMAL(12,2))),
    SUM(IFNULL(stg.impressions, 0)),
    SUM(IFNULL(stg.clicks, 0)),
    ROUND(AVG(CAST(stg.ctr AS DECIMAL(5,2))), 2),
    SUM(IFNULL(stg.visitors, 0)),
    SUM(IFNULL(stg.page_views, 0)),
    SUM(IFNULL(stg.add_to_cart_count, 0)),
    ROUND(AVG(CAST(stg.atc_conv_rate AS DECIMAL(5,2))), 2),
    SUM(IFNULL(stg.conversions, 0)),
    SUM(IFNULL(stg.confirmed_order, 0)),
    SUM(IFNULL(stg.units_placed_order, 0)),
    SUM(IFNULL(stg.buyers_placed_order, 0)),
    ROUND(AVG(CAST(stg.bounce_rate AS DECIMAL(5,2))), 2),
    ROUND(AVG(CAST(stg.repeat_order_rate_confirmed AS DECIMAL(5,2))), 2),
    SUM(IFNULL(stg.likes, 0)),
    SUM(IFNULL(stg.search_clicks, 0)),
    ROUND(AVG(CAST(stg.sales_per_order_confirmed AS DECIMAL(10,2))), 2)
FROM stg_product_traffic stg
WHERE stg.item_id IS NOT NULL
  AND stg.y_month IS NOT NULL
GROUP BY stg.y_month, stg.item_id;


SHOW CREATE TABLE dwh_product_traffic;

-- ==================== 4.3 产品聚合表构建 ====================

-- Step 1: 从产品流量表聚合流量指标 → 插入dwh_products
-- v3修正: total_impression → total_impressions (拼写修正)
-- ★ 关键修复: 原代码 pt.item_id = CAST(stg.item_id AS CHAR) 是明文=明文
--   加密后 pt.item_id 是密文, stg.item_id 是明文, 必须对 stg 端也加密后再 JOIN
-- ★ 同时修复: 原代码 y_month JOIN 用了错误的格式 '%YYYY-%MM-%DD', 已修正

INSERT INTO dwh_products (
    product_id, product_name, category, parent_sku,
    total_impressions, total_clicks, total_visitors,
    total_page_views, total_add_to_cart,
    avg_ctr, avg_cvr, avg_bounce_rate, avg_repeat_rate, total_likes
)
SELECT
    pt.item_id,
    MAX(pt.product_name),
    MAX(pt.category),
        -- ★ 加密: parent_sku 来自 stg 明文, 需加密后入库
    --   先聚合取 MAX(明文) 再加密, 避免对每条 variation 分别加密后取 MAX 导致不一致
    f_enc(max(stg.parent_sku)) as parent_sku,
    SUM(IFNULL(pt.impressions, 0)),
    SUM(IFNULL(pt.clicks, 0)),
    SUM(IFNULL(pt.visitors, 0)),
    SUM(IFNULL(pt.page_views, 0)),
    SUM(IFNULL(pt.add_to_cart, 0)),
    ROUND(AVG(IFNULL(pt.ctr, 0)), 2),
    ROUND(AVG(IFNULL(pt.conversions, 0)) * 100.0 / NULLIF(SUM(IFNULL(pt.visitors, 0)), 0), 2),
    ROUND(AVG(IFNULL(pt.bounce_rate, 0)), 2),
    ROUND(AVG(IFNULL(pt.repeat_rate, 0)), 2),
    SUM(IFNULL(pt.likes, 0))
FROM dwh_product_traffic pt
LEFT JOIN stg_product_traffic stg
    -- ★ 关键: dwh端密文 = f_enc(stg端明文), 确定性加密保证匹配
    ON pt.item_id = f_enc(stg.item_id)
    -- ON pt.item_id COLLATE utf8mb4_unicode_ci = CAST(stg.item_id AS CHAR) COLLATE utf8mb4_unicode_ci
-- ★ 修复: y_month 比较, stg.y_month 已是 'YYYY-MM-DD' 字符串, pt.y_month 是 DATE
    AND pt.y_month = STR_TO_DATE(stg.y_month, '%Y-%m-%d')
GROUP BY pt.item_id;


-- Step 2: 从订单表聚合销售指标 → UPDATE dwh_products
-- ⚠️ 这一步填充 total_revenue, total_orders, total_units, total_buyers
-- ⚠️ 前提: Part 4.1 已执行, dwh_orders 有数据
-- ⚠️ 如果 dwh_orders 为空, 这里UPDATE 0行, total_revenue 保持NULL
--
-- v3关键修正: JOIN条件添加 COLLATE utf8mb4_unicode_ci
-- 原因: dwh_products.product_id 来自 dwh_product_traffic.item_id (经CAST产生)
--       dwh_orders.product_id 来自 stg_orders.product_id (直接从表读取)
--       两者的排序规则(collation)可能不同, 导致JOIN匹配0行
INSERT INTO dwh_products (product_id, total_revenue, total_orders, total_units, total_buyers)
SELECT
    product_id,
    SUM(IFNULL(final_price, 0)) AS total_revenue,
    COUNT(DISTINCT order_id) AS total_orders,
    SUM(IFNULL(quantity, 0)) AS total_units,
    COUNT(DISTINCT username) AS total_buyers
FROM dwh_orders
WHERE is_completed = 1
  AND product_id IS NOT NULL
GROUP BY product_id
ON DUPLICATE KEY UPDATE
    total_revenue = VALUES(total_revenue),
    total_orders = VALUES(total_orders),
    total_units = VALUES(total_units),
    total_buyers = VALUES(total_buyers);

# SELECT
#   COUNT(*) AS total_products,
#    SUM(CASE WHEN total_revenue IS NOT NULL AND total_revenue > 0 THEN 1 ELSE 0 END) AS products_with_revenue,
# sum(case when total_revenue  is not null or total_revenue=0 then 1 else 0 end) as product_without_revenue
# from dwh_products;

-- Step 3: 计算价格带
-- v4修正: 用 INSERT...ON DUPLICATE KEY UPDATE 替代 UPDATE...JOIN
INSERT INTO dwh_products (product_id, price_band)
SELECT
    product_id,
    CASE
        WHEN MAX(sale_price) < 200 THEN 'Budget (<200 THB)'
        WHEN MAX(sale_price) BETWEEN 200 AND 399 THEN 'Low (200-399 THB)'
        WHEN MAX(sale_price) BETWEEN 400 AND 599 THEN 'Mid (400-599 THB)'
        WHEN MAX(sale_price) BETWEEN 600 AND 999 THEN 'High (600-999 THB)'
        WHEN MAX(sale_price) >= 1000 THEN 'Premium (1000+ THB)'
        ELSE 'Unknown'
    END AS price_band
FROM stg_orders
WHERE sale_price > 0
  AND product_id IS NOT NULL
GROUP BY product_id
ON DUPLICATE KEY UPDATE
    price_band = VALUES(price_band);

-- Step 4: ABC分类 (按累计销售额帕累托)
-- v4修正: 用 INSERT...ON DUPLICATE KEY UPDATE 替代 UPDATE...JOIN
INSERT INTO dwh_products (product_id, abc_class)
SELECT
    product_id,
    CASE
        WHEN cum_pct <= 65 THEN 'A'
        WHEN cum_pct <= 90 THEN 'B'
        ELSE 'C'
    END AS abc_class
FROM (
    SELECT
        product_id,
        (SUM(total_revenue) OVER (ORDER BY total_revenue DESC)
         / (SELECT SUM(total_revenue) FROM dwh_products WHERE total_revenue IS NOT NULL) * 100) AS cum_pct
    FROM dwh_products
    WHERE total_revenue IS NOT NULL AND total_revenue > 0
) ranked
ON DUPLICATE KEY UPDATE
    abc_class = VALUES(abc_class);

-- ==================== 5.1 销售总览 ====================
SELECT
    COUNT(DISTINCT order_id) AS total_orders,
    SUM(final_price) AS total_revenue,
    SUM(quantity) AS total_units,
    COUNT(DISTINCT username) AS total_buyers,
    COUNT(DISTINCT product_id) AS total_products,
    ROUND(SUM(final_price) / COUNT(DISTINCT order_id), 2) AS aov
FROM dwh_orders
WHERE is_completed = 1 and order_date <='2026-07-01';

-- ==================== 5.2 月度销售趋势 ====================
SELECT
    order_month,
    COUNT(DISTINCT order_id) AS total_orders,
    SUM(final_price) AS total_revenue,
    SUM(quantity) AS total_units,
    ROUND(SUM(final_price) / COUNT(DISTINCT order_id), 2) AS aov
FROM dwh_orders
WHERE is_completed = 1
GROUP BY order_month
ORDER BY order_month;

-- ==================== 5.3 订单状态分布 ====================
SELECT
    status_en,
    COUNT(*) AS row_count,
    COUNT(DISTINCT order_id) AS order_count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM dwh_orders), 2) AS pct
FROM dwh_orders
GROUP BY status_en
ORDER BY order_count DESC;

-- ==================== 5.4 取消原因分析 ====================
SELECT
    cancel_reason,
    COUNT(DISTINCT order_id) AS order_count,
    ROUND(COUNT(DISTINCT order_id) * 100.0 /
        (SELECT COUNT(DISTINCT order_id) FROM dwh_orders WHERE status_en = 'Cancelled'), 2) AS pct
FROM dwh_orders
WHERE status_en = 'Cancelled'
  AND cancel_reason IS NOT NULL
GROUP BY cancel_reason
ORDER BY order_count DESC
LIMIT 10;

-- ==================== 5.5 ABC分类汇总 ====================
select
    p.abc_class,
    count(*) as product_count,
    round(count(*)*100.0/(select count(*) from dwh_products),2) as product_pct,
    sum(ifnull(p.total_revenue,0)) as total_revenue,
    round(sum(ifnull(p.total_revenue,0))*100.0/
          (select sum(total_revenue) from dwh_products where total_revenue is not null),2) as revenue_pct,
    round(avg(ifnull(p.total_clicks,0)/nullif(p.total_impressions,0)*100),2) as avg_ctr,
    round(avg(ifnull(p.total_revenue,0)/nullif(p.total_orders,0)),2) as avg_aov
from dwh_products p
where p.abc_class is not null
group by p.abc_class
order by p.abc_class;

-- ==================== 5.6 价格带分析 ====================

select
    price_band,
    count(distinct product_id) as product_count,
    count(distinct order_id) as total_orders,
    sum(final_price) as totoal_revenue,
    round(sum(final_price)/count(distinct order_id),2) as aov,
    round(sum(final_price)*100.0/
          (select sum(final_price) from dwh_orders where is_completed=1),2) as revenue_pct
from dwh_orders
where is_completed=1
group by price_band
order by min(sale_price);

-- ==================== 5.7 TOP 20 畅销商品 ====================
-- ★ 需要展示商品名时用 f_dec() 解密; product_id 也可解密用于溯源
select
    f_dec(p.product_id) AS product_id_plain,         -- 解密展示明文ID (授权用户)
    f_dec(p.product_name) AS product_name_plain,      -- 解密展示明文商品名
    p.product_id,
    p.category,
    p.price_band,
    p.abc_class,
    ifnull(p.total_revenue,0) as total_revenue,
    ifnull(p.total_orders,0) as total_orders,
    ifnull(p.total_units,0) as total_units,
    ifnull(p.total_buyers,0) as total_buyers,
    p.avg_ctr,
    p.avg_cvr,
    p.avg_repeat_rate
from dwh_products p
where p.total_revenue is not null and p.total_revenue >0
order by p.total_revenue desc
limit 10;

-- ==================== 5.8 转化漏斗分析 ====================
SELECT
    SUM(total_impressions) AS impressions,
    SUM(total_clicks) AS clicks,
    ROUND(SUM(total_clicks) * 100.0 / NULLIF(SUM(total_impressions), 0), 2) AS ctr_pct,
    SUM(total_visitors) AS visitors,
    ROUND(SUM(total_visitors) * 100.0 / NULLIF(SUM(total_clicks), 0), 2) AS click_to_visitor_pct,
    SUM(total_add_to_cart) AS add_to_cart,
    ROUND(SUM(total_add_to_cart) * 100.0 / NULLIF(SUM(total_visitors), 0), 2) AS atc_rate_pct,
    SUM(IFNULL(total_orders, 0)) AS orders,
    ROUND(SUM(IFNULL(total_orders, 0)) * 100.0 / NULLIF(SUM(total_add_to_cart), 0), 2) AS atc_to_order_pct,
    ROUND(SUM(IFNULL(total_orders, 0)) * 100.0 / NULLIF(SUM(total_visitors), 0), 2) AS overall_cvr_pct
FROM dwh_products;

-- ==================== 5.9 月度流量趋势 ====================
 select
     y_month,
     sum(impressions) as total_impressions,
         SUM(clicks) AS total_clicks,
    SUM(visitors) AS total_visitors,
    SUM(add_to_cart) AS total_add_to_cart,
    SUM(conversions) AS total_orders,
    ROUND(SUM(clicks) * 100.0 / NULLIF(SUM(impressions), 0), 2) AS ctr_pct,
    ROUND(SUM(conversions) * 100.0 / NULLIF(SUM(visitors), 0), 2) AS cvr_pct
FROM dwh_product_traffic
GROUP BY y_month
ORDER BY y_month;

-- ==================== 5.10 省份分布分析 ====================
SELECT
    province,
    COUNT(DISTINCT order_id) AS order_count,
    SUM(final_price) AS total_revenue,
    ROUND(SUM(final_price) / COUNT(DISTINCT order_id), 2) AS avg_order_value,
    COUNT(DISTINCT username) AS buyer_count,
    ROUND(SUM(final_price) * 100.0 /
        (SELECT SUM(final_price) FROM dwh_orders WHERE is_completed = 1), 2) AS revenue_pct
FROM dwh_orders
WHERE is_completed = 1
  AND province IS NOT NULL
  AND province != ''
GROUP BY province
ORDER BY total_revenue DESC
LIMIT 20;


-- ==================== 5.11 支付方式分析 ====================
select
    payment_channel_en,
    count(distinct order_id) as order_count,
    sum(final_price) as total_revenue,
    round(sum(final_price)/count(distinct order_id),2) as aov,
    round(count(distinct order_id)*100.0/(select count(distinct order_id) from dwh_orders where is_completed=1),2) as order_pct
from dwh_orders
where is_completed=1
group by payment_channel_en
order by total_revenue desc;

-- ==================== 5.12 促销折扣分析 ====================
select
    'Seller Coupon' as discount_type,
    count(distinct order_id) as order_count,
    round(count(distinct order_id)*100.0/
          (select count(distinct order_id) from dwh_orders where is_completed =1),2) as usage_rate_pct,
    round(avg(seller_coupon_amount),2) as avg_discount_amount
from dwh_orders where is_completed=1 and has_seller_coupon=1
union all
select
    'Voucher',
    count(distinct order_id),
    round(count(distinct order_id)*100.0/
          (select count(distinct order_id) from dwh_orders where is_completed=1),2),
    round(avg(voucher_amount),2)
from dwh_orders where is_completed=1 and has_voucher=1
union all
select
    'Shopee Discount',
    count(distinct order_id),
    round(count(distinct order_id)*100.0/
          (select count(distinct order_id) from dwh_orders where is_completed=1),2),
    round(avg(shopee_discount_amount),2)
from dwh_orders where is_completed=1 and has_shopee_discount=1
union all
select
    'Bundle Deal',
    count(distinct order_id),
    round(count(distinct order_id)*100.0/
          (select count(distinct order_id) from dwh_orders where is_completed=1),2),
    0
from dwh_orders where is_completed=1 and has_bundle_deal=1;

select
    case when has_any_discount=1 then 'With Discount' else 'No Discount' end as discount_status,
    count(distinct order_id) as order_count,
    sum(final_price) as total_revenue,
    round(sum(final_price)/count(distinct order_id),2) as aov
from dwh_orders
where is_completed=1
group by has_any_discount;


 -- 促销的深度分析
-- 不同折扣深度：订单数量、订单占比、AOV(客单价)、成交营收
SELECT
    CASE
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 < 5 THEN '<5%'
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 < 10 THEN '5‑10%'
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100< 20 THEN '10‑20%'
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 >= 20 THEN '20%+'
        ELSE '无折扣'
    END AS discount_depth,
    COUNT(DISTINCT order_id) AS total_orders,
    -- 该区间订单占全部有效订单的百分比
    ROUND(COUNT(DISTINCT order_id) * 100.0 / SUM(COUNT(DISTINCT order_id)) OVER(),2) AS order_pct,
    SUM(final_price) AS total_revenue,
    -- AOV 客单价
    ROUND(SUM(final_price) / NULLIF(COUNT(DISTINCT order_id),0),2) AS aov
FROM dwh_orders
WHERE
    is_completed = 1
    AND original_price > 0 and order_date >'2026-07-01' -- 排除原价0异常脏数据
GROUP BY discount_depth
ORDER BY
    -- 自定义排序，按折扣从小到大
    CASE discount_depth
        WHEN '<5%' THEN 1
        WHEN '5‑10%' THEN 2
        WHEN '10‑20%' THEN 3
        WHEN '20%+' THEN 4
        WHEN '无折扣' THEN 0
    END;

-- ==================== 5.13 RFM客户分群 ====================
with rfm as(
    select username,
           datediff(curdate(),max(order_date)) as recency,
           count(distinct order_id) as frequency,
           sum(final_price) as monetary
    from dwh_orders
    where is_completed=1 and order_date <='2026-07-01'
    group by username
),
scored as(
    select username,recency,frequency,monetary,
           ntile(5) over(order by recency desc) as r_score,
           ntile(5) over(order by frequency ) as f_score,
           ntile(5) over(order by monetary)as m_score
    from rfm
)
select
    case
        when r_score>=4 and f_score >=4 and m_score >=4 then 'Champions'
        WHEN r_score >= 3 AND f_score >= 3 AND m_score >= 3 THEN 'Loyal'
        WHEN r_score >= 4 AND f_score <= 2 THEN 'New Customers'
        WHEN r_score >= 3 AND m_score >= 3 THEN 'Potential Loyalist'
        WHEN r_score <= 2 AND f_score >= 3 AND m_score >= 3 THEN 'At Risk'
        WHEN r_score <= 2 AND f_score <= 2 THEN 'Hibernating'
        WHEN m_score >= 4 THEN 'Big Spenders'
        ELSE 'Need Attention'
    end as segment,
    count(*) as customer_count,
    round(count(*)*100.0/
          (select count(*) from rfm),2) as pct,
    round(avg(recency),1) as avg_recency_days,
    round(avg(frequency),1) as avg_frequency,
    round(avg(monetary),2) as avg_monetary,
    sum(monetary) as total_monetary
from scored
group by segment
order by customer_count desc;

-- ==================== 5.14 时段分析 ====================
select order_hour,
       count(distinct order_id) as order_count,
       sum(final_price) as total_revenue
from dwh_orders
where is_completed=1
group by order_hour
order by order_hour;
select order_weekday,
       count(distinct order_id) as order_count,
       sum(final_price) as total_revenue,
       is_weekend
from dwh_orders
where is_completed=1
group by order_weekday, is_weekend
order by field(order_weekday,'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday');

-- ==================== 5.15 产品分类分析 ====================
select category,
       count(distinct product_id) as product_count,
       count(distinct order_id) as order_count,
       sum(final_price) as total_revenue,
       sum(quantity) as total_units,
       round(sum(final_price)*100.0/
             (select sum(final_price) from dwh_orders where is_completed=1),2) as revenue_pct
from dwh_orders
where is_completed=1 and order_date <'2026-07-01'
group by category
order by total_revenue desc;

-- ==================== 5.16 复购率与跳出率分析 ====================
 select  p.product_id,

    p.abc_class,
    p.total_revenue,
    p.avg_ctr,
    p.avg_cvr,
    p.avg_bounce_rate,
    p.avg_repeat_rate,
    p.total_likes,
    p.total_add_to_cart
 from dwh_products p
 where p.total_revenue is not null and p.total_revenue>0
 order by  p.total_revenue desc
 limit 20;

-- ====================tableau需要创建新视图====================
CREATE VIEW view_rfm_segment AS
with rfm as(
    select username,
           datediff(curdate(),max(order_date)) as recency,
           count(distinct order_id) as frequency,
           sum(final_price) as monetary
    from dwh_orders
    where is_completed=1
    group by username
),
scored as(
    select username,recency,frequency,monetary,
           ntile(5) over(order by recency desc) as r_score,
           ntile(5) over(order by frequency ) as f_score,
           ntile(5) over(order by monetary)as m_score
    from rfm
)
select
    case
        when r_score>=4 and f_score >=4 and m_score >=4 then 'Champions'
        WHEN r_score >= 3 AND f_score >= 3 AND m_score >= 3 THEN 'Loyal'
        WHEN r_score >= 4 AND f_score <= 2 THEN 'New Customers'
        WHEN r_score >= 3 AND m_score >= 3 THEN 'Potential Loyalist'
        WHEN r_score <= 2 AND f_score >= 3 AND m_score >= 3 THEN 'At Risk'
        WHEN r_score <= 2 AND f_score <= 2 THEN 'Hibernating'
        WHEN m_score >= 4 THEN 'Big Spenders'
        ELSE 'Need Attention'
    end as segment,
    count(*) as customer_count,
    round(count(*)*100.0/
          (select count(*) from rfm),2) as pct,
    round(avg(recency),1) as avg_recency_days,
    round(avg(frequency),1) as avg_frequency,
    round(avg(monetary),2) as avg_monetary,
    sum(monetary) as total_monetary
from scored
group by segment;


-- ====================tableau需要创建新视图====================
 CREATE VIEW view_rfm_user_detail AS
WITH rfm AS(
    SELECT username,
           DATEDIFF(CURDATE(),MAX(order_date)) AS recency,
           COUNT(DISTINCT order_id) AS frequency,
           SUM(final_price) AS monetary
    FROM dwh_orders
    WHERE is_completed=1
    GROUP BY username
),
scored AS(
    SELECT
        username,
        recency,
        frequency,
        monetary,
        NTILE(5) OVER(ORDER BY recency DESC) AS r_score,
        NTILE(5) OVER(ORDER BY frequency) AS f_score,
        NTILE(5) OVER(ORDER BY monetary) AS m_score
    FROM rfm
)
SELECT
    *,
    CASE
        WHEN r_score>=4 AND f_score >=4 AND m_score >=4 THEN 'Champions'
        WHEN r_score >= 3 AND f_score >= 3 AND m_score >= 3 THEN 'Loyal'
        WHEN r_score >= 4 AND f_score <= 2 THEN 'New Customers'
        WHEN r_score >= 3 AND m_score >= 3 THEN 'Potential Loyalist'
        WHEN r_score <= 2 AND f_score >= 3 AND m_score >= 3 THEN 'At Risk'
        WHEN r_score <= 2 AND f_score <= 2 THEN 'Hibernating'
        WHEN m_score >= 4 THEN 'Big Spenders'
        ELSE 'Need Attention'
    END AS segment
FROM scored;


-- ====================流量漏斗转化图视图====================
CREATE VIEW view_product_funnel AS
WITH stage_data AS (
    SELECT '曝光' AS funnel_stage, 1 AS stage_sort, SUM(total_impressions) AS metric_value FROM dwh_products
    UNION ALL
    SELECT '点击' AS funnel_stage, 2 AS stage_sort, SUM(total_clicks) AS metric_value FROM dwh_products
    UNION ALL
    SELECT '访客' AS funnel_stage, 3 AS stage_sort, SUM(total_visitors) AS metric_value FROM dwh_products
    UNION ALL
    SELECT '加购' AS funnel_stage, 4 AS stage_sort, SUM(total_add_to_cart) AS metric_value FROM dwh_products
    UNION ALL
    SELECT '下单' AS funnel_stage, 5 AS stage_sort, SUM(total_orders) AS metric_value FROM dwh_products
),
lag_calc AS (
    SELECT
        funnel_stage,
        stage_sort,
        metric_value,
        LAG(metric_value) OVER(ORDER BY stage_sort) AS prev_metric
    FROM stage_data
)
SELECT
    funnel_stage,
    stage_sort,
    metric_value,
    -- 环节转化率：当前 / 上一步
    ROUND(
        CASE WHEN prev_metric IS NULL THEN NULL ELSE metric_value / prev_metric END
        ,4) AS step_convert_rate,
    -- 整体转化率：当前 / 曝光
    ROUND(metric_value / FIRST_VALUE(metric_value) OVER(ORDER BY stage_sort),4) AS total_convert_rate
FROM lag_calc
ORDER BY stage_sort;


-- ====================产品流量漏斗转化图视图===================
DROP VIEW IF EXISTS view_funnel_product_filter;

CREATE VIEW view_funnel_product_filter AS
WITH raw_funnel AS (
    SELECT
        product_id,
        product_name,
        '曝光' AS funnel_stage,
        1 AS stage_sort,
        COALESCE(total_impressions, 0) AS metric_value
    FROM dwh_products

    UNION ALL
    SELECT
        product_id,
        product_name,
        '点击' AS funnel_stage,
        2 AS stage_sort,
        COALESCE(total_clicks, 0) AS metric_value
    FROM dwh_products

    UNION ALL
    SELECT
        product_id,
        product_name,
        '访客' AS funnel_stage,
        3 AS stage_sort,
        COALESCE(total_visitors, 0) AS metric_value
    FROM dwh_products

    UNION ALL
    SELECT
        product_id,
        product_name,
        '加购' AS funnel_stage,
        4 AS stage_sort,
        COALESCE(total_add_to_cart, 0) AS metric_value
    FROM dwh_products

    UNION ALL
    SELECT
        product_id,
        product_name,
        '下单' AS funnel_stage,
        5 AS stage_sort,
        COALESCE(total_orders, 0) AS metric_value
    FROM dwh_products
)
SELECT
    product_id,
    product_name,
    funnel_stage,
    stage_sort,
    metric_value,
    -- 上一环节转化率，每个产品分区计算
    ROUND(
        CASE
            WHEN LAG(metric_value) OVER(PARTITION BY product_id ORDER BY stage_sort) IS NULL
            THEN NULL
            ELSE metric_value / LAG(metric_value) OVER(PARTITION BY product_id ORDER BY stage_sort)
        END, 4
    ) AS step_convert_rate,
    -- 相对曝光的整体转化率
    ROUND(
        metric_value / FIRST_VALUE(metric_value) OVER(PARTITION BY product_id ORDER BY stage_sort),
        4
    ) AS total_convert_rate
FROM raw_funnel;

select date(order_date) as dt,
       case
           when date(order_date) between '2026-04-01' and '2026-04-09' then '宋干节前'
           when date(order_date) between '2026-04-10' and '2026-04-19' then '宋干节期间'
           when date(order_date) between '2026-04-20' and '2026-04-30' then '宋干节后'
            else '其他'
       end as stage,
       sum(final_price) as daily_gmv
from dwh_orders
where is_completed=1
and order_date >='2026-04-01'
and order_date <='2026-05-01'
group by dt,stage
order by dt desc;

select sum(final_price) as total_gmv_mar,
       count(distinct date(order_date)) as valid_day_cnt,
       round(sum(final_price)/count(distinct date(order_date)),2) as avg_daily_gmv_mar
from dwh_orders
where is_completed=1
and order_date >='2026-03-01'
and order_date <='2026-03-31';


-- ====================验证6月客单价上涨是高价订单占比上升===================
select
    date_format(order_date,'%Y-%M') as stat_month,

    sum(case when final_price between 0 and 200 then 1 else 0 end) as low_cnt,
    round(sum(case when final_price between 0 and 299 then 1 else 0 end)/count(distinct order_id)*100,2) as low_pct,

    sum(case when final_price between 300 and 599 then 1 else 0 end) as mid_cnt,
    round(sum(case when final_price between 300 and 599 then 1 else 0 end)/count(distinct order_id)*100,2) as mid_pct,

    sum(case when final_price between 600 and 999 then 1 else 0 end) as high_cnt,
    round(sum(case when final_price between 600 and 999 then 1 else 0 end)/count(distinct order_id)*100,2) as high_pct
from dwh_orders
WHERE
    is_completed = 0
    AND order_date >= '2026-05-01'
    AND order_date< '2026-07-01'
GROUP BY stat_month
ORDER BY stat_month;



SELECT
    CASE
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 < 5 THEN '<5%'
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 < 10 THEN '5-10%'
    WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 < 20 THEN '10-20%'
        WHEN (seller_coupon_amount + voucher_amount + shopee_discount_amount) / NULLIF(original_price,0) * 100 >= 20 THEN '20%+'
    END AS discount_depth,
    COUNT(DISTINCT order_id) AS orders,
    SUM(final_price) AS revenue
FROM dwh_orders WHERE is_completed = 1 AND original_price > 0
GROUP BY discount_depth;

--
-- ====================求平均复购率===================
SELECT
    ROUND(AVG(repeat_rate),2) AS avg_repurchase_rate,
    ROUND(AVG(bounce_rate),2)     AS avg_bounce_rate
FROM dwh_product_traffic;
 -- 复购率和跳出率的交叉分析
 WITH shop_avg AS (
    SELECT
        AVG(repeat_rate) AS avg_rr,
        AVG(bounce_rate) AS avg_br
    FROM dwh_product_traffic
)
SELECT
    fps.item_id,
    fps.repeat_rate,
    fps.bounce_rate,
    fps.sales_placed,
    -- 四象限打标签
    CASE
        WHEN repeat_rate > 0.12 AND bounce_rate < 0.2 THEN '高复购+低跳出｜优质商品，加大推广预算'
        WHEN repeat_rate > 0.12 AND bounce_rate >= 0.2 THEN '高复购+高跳出｜老客忠诚，优化主图标题'
        WHEN repeat_rate <= 0.12 AND bounce_rate < 0.2 THEN '低复购+低跳出｜新客浏览不复购，核查价格品质评价'
        WHEN repeat_rate <= 0.12 AND bounce_rate >= 0.2 THEN '低复购+高跳出｜双低，考虑清仓下架'
    END AS product_tag
FROM dwh_product_traffic fps, shop_avg sa
ORDER BY fps.sales_placed DESC
LIMIT 20;

 -- -- ====================价格带 * 地段的交叉分析===================
 SELECT province, price_band,
       COUNT(DISTINCT order_id) AS orders,
       SUM(final_price) AS revenue,
       round(count(distinct order_id)*100.0/sum(count(distinct order_id))over(),2) as order_pct_total
FROM dwh_orders WHERE is_completed = 1
GROUP BY province, price_band
ORDER BY revenue DESC
limit
 20;

 --   ====================交叉2：支付方式 × AOV × 价格带===================
SELECT
    payment_channel_en,
    price_band,
    COUNT(DISTINCT order_id) AS orders,
    ROUND(SUM(final_price)/COUNT(DISTINCT order_id), 2) AS aov,
    ROUND(COUNT(DISTINCT order_id)*100.0/SUM(COUNT(DISTINCT order_id))OVER(),2) AS order_pct
FROM dwh_orders
WHERE is_completed = 1
GROUP BY payment_channel_en, price_band
ORDER BY
    CASE payment_channel_en
        WHEN 'SPayLater' THEN 1
        WHEN 'cod' THEN 2
        WHEN 'Credit/Debit Card' THEN 3
        WHEN 'Mobile Banking' THEN 4
        WHEN 'QR PromptPay' THEN 5
        WHEN 'ShopeePay (Bank)' THEN 6
        WHEN 'ShopeePay Balance' THEN 7
        ELSE 99  -- 其它未知支付渠道放最后
    END,
    price_band DESC;

 -- ====================ABC分类 ×流量漏斗==================
 SELECT p.abc_class,
       SUM(p.total_impressions) AS impressions,
       SUM(p.total_clicks) AS clicks,
       ROUND(SUM(p.total_clicks)*100.0/NULLIF(SUM(p.total_impressions),0), 2) AS ctr,
       SUM(p.total_visitors) AS visitors,
       SUM(IFNULL(p.total_orders,0)) AS orders,
       ROUND(SUM(IFNULL(p.total_orders,0))*100.0/NULLIF(SUM(p.total_visitors),0), 2) AS cvr
FROM dwh_products p WHERE p.abc_class IS NOT NULL
GROUP BY p.abc_class ORDER BY p.abc_class;


 -- ====================时段 × 星期==================
SELECT
    order_weekday,
    order_hour,
    COUNT(DISTINCT order_id) AS orders,
    SUM(final_price) AS revenue
FROM dwh_orders
WHERE is_completed = 1
GROUP BY order_weekday, order_hour
ORDER BY
    FIELD(order_weekday, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'),
    order_hour;

 -- ====================清仓款销量验证==================
 -- 清仓款销量验证
 -- 验证：20%+折扣订单集中在哪些商品？
SELECT product_name, COUNT(*) order_cnt, AVG(final_price) aov
FROM dwh_orders
WHERE has_any_discount = 1
  AND (seller_coupon_amount + voucher_amount + shopee_discount_amount)
      / NULLIF(original_price,0) >= 0.2
GROUP BY product_name
ORDER BY order_cnt DESC
LIMIT 10;

-- ============================================================
-- PART 7: 加密验证脚本 (ETL完成后执行)
-- 验证目标: 确定性、JOIN正确性、聚合正确性、明文不可读
-- ============================================================

-- 7.1 验证确定性加密: 同明文必须产生同密文
SELECT
    '确定性加密验证' AS test_name,
    CASE WHEN f_enc('1234567890') = f_enc('1234567890') THEN 'PASS' ELSE 'FAIL' END AS result;

-- 7.2 验证不同明文产生不同密文
SELECT
    '不同明文差异化验证' AS test_name,
    CASE WHEN f_enc('1111111111') <> f_enc('2222222222') THEN 'PASS' ELSE 'FAIL' END AS result;

-- 7.3 验证加解密往返一致性
SELECT
    '加解密往返验证' AS test_name,
    CASE WHEN f_dec(f_enc('Shopee_Test_Product_001')) = 'Shopee_Test_Product_001'
         THEN 'PASS' ELSE 'FAIL' END AS result;

-- 7.4 验证NULL处理
SELECT
    'NULL加密验证' AS test_name,
    CASE WHEN f_enc(NULL) IS NULL AND f_dec(NULL) IS NULL THEN 'PASS' ELSE 'FAIL' END AS result;

-- 7.5 验证跨表JOIN: dwh_orders.product_id (密文) = dwh_products.product_id (密文)
--    统计能匹配上的订单行数, 应接近 dwh_orders 总行数
SELECT
    '跨表JOIN匹配率' AS test_name,
    CONCAT(ROUND(
        (SELECT COUNT(*) FROM dwh_orders o
         INNER JOIN dwh_products p ON o.product_id = p.product_id
         WHERE o.product_id IS NOT NULL) * 100.0 /
        NULLIF((SELECT COUNT(*) FROM dwh_orders WHERE product_id IS NOT NULL), 0), 2
    ), '%') AS match_rate;

-- 7.6 验证 dwh_product_traffic.item_id 与 dwh_orders.product_id 可关联
--    (同一批Shopee Item ID, 用同一密钥加密, 密文应一致)
SELECT
    '流量表-订单表ID关联验证' AS test_name,
    COUNT(DISTINCT pt.item_id) AS matched_item_count
FROM dwh_product_traffic pt
INNER JOIN dwh_orders o ON pt.item_id = o.product_id
WHERE pt.item_id IS NOT NULL;

-- 7.7 验证聚合正确性: 密文GROUP BY不影响数值聚合
--    对比 dwh_products.total_revenue 与从 dwh_orders 直接聚合的结果
SELECT
    '聚合数值一致性验证' AS test_name,
    ABS(SUM(p.total_revenue) - (SELECT SUM(final_price) FROM dwh_orders WHERE is_completed = 1)) AS revenue_diff
FROM dwh_products p
WHERE p.total_revenue IS NOT NULL;
-- revenue_diff 应为 0 或极小值(浮点误差)

-- 7.8 验证明文不可直接读取: dwh_orders.product_name 不应包含可读商品名关键词
SELECT
    '明文不可读验证' AS test_name,
    CASE
        WHEN (SELECT COUNT(*) FROM dwh_orders
              WHERE product_name LIKE '%tote%' OR product_name LIKE '%bag%'
                 OR product_name LIKE '%กระเป๋า%' LIMIT 1) = 0
        THEN 'PASS (DWH层无明文商品名)' ELSE 'FAIL (检测到疑似明文)' END AS result;

-- 7.9 验证 dwh_products 主键唯一性 (确定性加密保证同ID同密文)
SELECT
    '主键唯一性验证' AS test_name,
    CASE WHEN COUNT(*) = COUNT(DISTINCT product_id) THEN 'PASS' ELSE 'FAIL' END AS result
FROM dwh_products;

-- 7.10 验证 STG 层仍为明文 (溯源层)
SELECT
    'STG明文保留验证' AS test_name,
    CASE WHEN (SELECT COUNT(*) FROM stg_orders
               WHERE product_name LIKE '%tote%' LIMIT 1) > 0
         THEN 'PASS (STG层保留明文)' ELSE 'CHECK (STG层可能无tote商品)' END AS result;


-- ============================================================
-- PART 8: 解密示例 (仅授权用户执行)
-- ⚠️ 执行前必须已运行 PART 0 (设置 @aes_key 和 block_encryption_mode)
-- ============================================================

-- 8.1 查看某订单的明文商品信息 (按 order_id 查)
SELECT
    o.order_id,
    f_dec(o.product_id) AS product_id_plain,
    f_dec(o.product_name) AS product_name_plain,
    f_dec(o.sku) AS sku_plain,
    o.category,
    o.final_price,
    o.order_date
FROM dwh_orders o
WHERE o.order_id = 'YOUR_ORDER_ID_HERE';

-- 8.2 查看某商品的明文信息及聚合指标
SELECT
    f_dec(p.product_id) AS product_id_plain,
    f_dec(p.product_name) AS product_name_plain,
    f_dec(p.parent_sku) AS parent_sku_plain,
    p.category,
    p.price_band,
    p.abc_class,
    p.total_revenue,
    p.total_orders,
    p.total_units
FROM dwh_products p
WHERE f_dec(p.product_id) = 'YOUR_PRODUCT_ID_HERE';  -- 用明文ID过滤(需解密后比较)

-- 8.3 高效按明文ID查询: 先加密明文再匹配密文 (避免全表解密)
--    这是生产环境推荐的查询方式: 对查询参数加密, 直接匹配密文字段(可走索引)
SELECT
    f_dec(p.product_id) AS product_id_plain,
    f_dec(p.product_name) AS product_name_plain,
    p.total_revenue,
    p.total_orders
FROM dwh_products p
WHERE p.product_id = f_enc('YOUR_PRODUCT_ID_HERE');  -- ★ 推荐: 加密查询参数, 可走索引

-- 8.4 导出脱敏报表: 商品名显示为密文(默认), 仅授权角色可解密
-- 普通分析师角色 (无解密权限) 看到的是:
SELECT product_id, category, price_band, total_revenue, total_orders
FROM dwh_products
ORDER BY total_revenue DESC
LIMIT 10;
-- product_id 显示为 Base64 密文字符串, 无法反推商品身份

-- 8.5 验证密钥错误时解密失败 (安全测试)
-- 临时设置错误密钥, 解密应返回 NULL 或乱码
SET @wrong_key = 'WRONG_KEY_FOR_TESTING_ONLY_123456';
SELECT
    f_dec((SELECT product_name FROM dwh_orders WHERE product_name IS NOT NULL LIMIT 1)) AS decrypted_with_wrong_key;
-- 应返回 NULL 或不可读乱码, 证明密钥错误时无法解密
-- 测试完恢复正确密钥:
SET @aes_key = 'ThShopeeDW2026SecureKey!@#$%^&*_';  -- 恢复为正确密钥(生产环境替换)


-- ============================================================================
-- 文件结束
-- 加密方案总结:
--   算法: AES-256-ECB (确定性)
--   存储: Base64 编码 → VARCHAR(255) / MEDIUMTEXT
--   范围: product_id, item_id, product_name, sku, parent_sku
--   时机: STG明文 → ETL加密 → DWH密文
--   密钥: 会话变量 @aes_key (32字节), 生产环境应接入KMS
--   解密: f_dec() 函数, 仅授权角色可执行
-- ============================================================================

TRUNCATE TABLE dwh_orders;
TRUNCATE TABLE dwh_product_traffic;
TRUNCATE TABLE dwh_products;