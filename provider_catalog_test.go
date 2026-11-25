package main

import (
	"sort"
	"strings"
	"testing"
)

// 目录必须按 acme.sh code 字母序排列，页面下拉直接沿用这个顺序。
func TestProviderCatalogSortedByCode(t *testing.T) {
	codes := make([]string, 0, len(providerCatalog))
	for _, p := range providerCatalog {
		codes = append(codes, p.Code)
	}
	sorted := append([]string(nil), codes...)
	sort.Strings(sorted)
	for i := range codes {
		if codes[i] != sorted[i] {
			t.Fatalf("服务商目录未按 code 排序：位置 %d 是 %s，应为 %s", i, codes[i], sorted[i])
		}
	}
}

// 目录里的每个 code 都必须是 acme.sh 真实存在的脚本名（历史错误码由 normalizeProviderCode 兜底）。
func TestProviderCatalogCodesAndWebsites(t *testing.T) {
	if len(providerCatalog) < 43 {
		t.Fatalf("服务商数量不足：%d", len(providerCatalog))
	}
	seen := map[string]bool{}
	for _, p := range providerCatalog {
		if seen[p.Code] {
			t.Errorf("重复的服务商 code: %s", p.Code)
		}
		seen[p.Code] = true
		if !strings.HasPrefix(p.Website, "https://") {
			t.Errorf("%s 的官网不是 https: %q", p.Code, p.Website)
		}
		if len(p.Fields) == 0 {
			t.Errorf("%s 没有凭证字段", p.Code)
		}
		for _, f := range p.Fields {
			if f.Name == "" || f.Label == "" {
				t.Errorf("%s 存在空字段名/标签", p.Code)
			}
		}
	}
	for _, legacy := range []string{"dns_do", "dns_gandi", "dns_linode"} {
		if seen[legacy] {
			t.Errorf("目录里仍在用失效的 acme.sh code: %s", legacy)
		}
	}
	for _, want := range []string{"dns_dgon", "dns_gandi_livedns", "dns_linode_v4", "dns_duckdns", "dns_pdns", "dns_nsupdate", "dns_jd", "dns_baidu", "dns_dpi"} {
		if !seen[want] {
			t.Errorf("缺少服务商 code: %s", want)
		}
	}
}

func TestLegacyProviderCodeNormalization(t *testing.T) {
	cases := map[string]string{
		"dns_do":         "dns_dgon",
		"dns_gandi":      "dns_gandi_livedns",
		"dns_linode":     "dns_linode_v4",
		"dns_cf":         "dns_cf",
		"dns_duckdns":    "dns_duckdns",
		"not-a-provider": "not-a-provider",
	}
	for in, want := range cases {
		if got := normalizeProviderCode(in); got != want {
			t.Errorf("normalizeProviderCode(%q) = %q, want %q", in, got, want)
		}
		if _, ok := providerByCode[normalizeProviderCode(in)]; in != "not-a-provider" && !ok {
			t.Errorf("归一后的 code 不在目录中: %q", in)
		}
	}
}

func TestProviderCredentialFieldNames(t *testing.T) {
	want := map[string][]string{
		"dns_dgon":          {"DO_API_KEY"},
		"dns_linode_v4":     {"LINODE_V4_API_KEY"},
		"dns_gandi_livedns": {"GANDI_LIVEDNS_TOKEN"},
		"dns_duckdns":       {"DuckDNS_Token"},
		"dns_pdns":          {"PDNS_Url", "PDNS_ServerId", "PDNS_Token"},
		"dns_nsupdate":      {"NSUPDATE_SERVER"},
		"dns_ovh":           {"OVH_AK", "OVH_AS", "OVH_CK", "OVH_END_POINT"},
		"dns_azure":         {"AZUREDNS_SUBSCRIPTIONID", "AZUREDNS_TENANTID", "AZUREDNS_APPID", "AZUREDNS_CLIENTSECRET"},
		"dns_netcup":        {"NC_CID", "NC_Apikey", "NC_Apipw"},
		"dns_inwx":          {"INWX_User", "INWX_Password"},
		"dns_dnsimple":      {"DNSimple_OAUTH_TOKEN"},
		"dns_acmedns":       {"ACMEDNS_SUBDOMAIN", "ACMEDNS_USERNAME", "ACMEDNS_PASSWORD"},
		"dns_jd":            {"JD_ACCESS_KEY_ID", "JD_ACCESS_KEY_SECRET"},
		"dns_vercel":        {"VERCEL_TOKEN"},
		"dns_netlify":       {"NETLIFY_ACCESS_TOKEN"},
		"dns_dynv6":         {"DYNV6_TOKEN"},
		"dns_df":            {"DF_user", "DF_password"},
		"dns_namesilo":      {"Namesilo_Key"},
		"dns_conoha":        {"CONOHA_Username", "CONOHA_Password", "CONOHA_TenantId", "CONOHA_IdentityServiceApi"},
		"dns_openprovider":  {"OPENPROVIDER_USER", "OPENPROVIDER_PASSWORDHASH"},
		"dns_mydnsjp":       {"MYDNSJP_MasterID", "MYDNSJP_Password"},
		"dns_easydns":       {"EASYDNS_Key", "EASYDNS_Token"},
		"dns_constellix":    {"CONSTELLIX_Key", "CONSTELLIX_Secret"},
		"dns_njalla":        {"NJALLA_Token"},
		"dns_arvan":         {"Arvan_Token"},
		"dns_baidu":         {"Baidu_AK", "Baidu_SK"},
		"dns_dpi":           {"DPI_Id", "DPI_Key"},
		"dns_ultra":         {"ULTRA_USR", "ULTRA_PWD"},
	}
	for code, fields := range want {
		def, ok := providerByCode[code]
		if !ok {
			t.Errorf("目录缺少 %s", code)
			continue
		}
		have := map[string]bool{}
		for _, f := range def.Fields {
			have[f.Name] = true
		}
		for _, f := range fields {
			if !have[f] {
				t.Errorf("%s 缺少凭证字段 %s", code, f)
			}
		}
	}
}
