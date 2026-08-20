use const_format::concatcp;

pub const ACCESS_MANAGER_KEY_EXPR_PREFIX: &str = "access_manager/";
pub const ACCESS_MANAGER_POLICY_KEY_EXPR_PREFIX: &str =
    concatcp!(ACCESS_MANAGER_KEY_EXPR_PREFIX, "policy/");
pub const ACCESS_MANAGER_POLICY_KEY_EXPR: &str =
    concatcp!(ACCESS_MANAGER_POLICY_KEY_EXPR_PREFIX, "**");

pub const ATTRIBUTE_AUTHORITY_KEY_EXPR_PREFIX: &str = "attr_authority/";
pub const ATTRIBUTE_AUTHORITY_PK_KEY_EXPR: &str =
    concatcp!(ATTRIBUTE_AUTHORITY_KEY_EXPR_PREFIX, "pk");
pub const ATTRIBUTE_AUTHORITY_SK_KEY_EXPR: &str =
    concatcp!(ATTRIBUTE_AUTHORITY_KEY_EXPR_PREFIX, "sk");

pub const HEADER_CK_ID: &str = "CK-ID";
pub const HEADER_PRODUCER_PREFIX: &str = "Producer-Prefix";
pub const HEADER_NEXT_CK_ID: &str = "Next-CK-ID";
