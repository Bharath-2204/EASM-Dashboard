import streamlit as st
import concurrent.futures
from core.config import settings
from core.models import ExtendedOSINTResult
from recon.ct_logs import fetch_ct_domains
from recon.tls_auditor import audit_tls_endpoint
from recon.shodan_passive import query_shodan_passive
from recon.github_leaks import scan_github_leaks
from intelligence.risk_engine import calculate_risk_score
from intelligence.ai_analyst import generate_mitre_briefing
from exporters.stix_formatter import generate_stix_bundle
from exporters.json_exporter import generate_json_export

st.set_page_config(page_title="EASM", page_icon="🛡️", layout="wide")

st.title("🛡️ EASM Dashboard")
st.caption("External Attack Surface Management & Threat Intelligence Platform")

# Sidebar - System Status & Credentials Verification
with st.sidebar:
    st.header("⚙️ Platform Health")
    
    gh_status = "🟢 Configured" if settings.GITHUB_TOKEN else "🟡 Public Only (Rate Limited)"
    shodan_status = "🟢 Configured" if settings.SHODAN_API_KEY else "🔴 Missing Key"
    aws_status = "🟢 Configured" if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY else "🔴 Missing Credentials"
    
    st.markdown(f"**GitHub API:** {gh_status}")
    st.markdown(f"**Shodan API:** {shodan_status}")
    st.markdown(f"**AWS Bedrock AI:** {aws_status}")
    st.caption("Secrets managed via `.streamlit/secrets.toml`")

# Target Input Form
target_domain = st.text_input("Target Domain", placeholder="example.com").strip().lower()

if st.button("Run Surface Reconnaissance", type="primary") and target_domain:
    st.divider()
    
    with st.spinner(f"Executing multi-threaded OSINT sweep against {target_domain}..."):
        with concurrent.futures.ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
            future_ct = executor.submit(fetch_ct_domains, target_domain)
            future_tls = executor.submit(audit_tls_endpoint, target_domain)
            future_shodan = executor.submit(query_shodan_passive, target_domain, settings.SHODAN_API_KEY)
            future_github = executor.submit(scan_github_leaks, target_domain, settings.GITHUB_TOKEN)

            ct_subdomains, ct_err = future_ct.result()
            tls_data, tls_err = future_tls.result()
            shodan_hosts, shodan_err = future_shodan.result()
            github_leaks, github_err = future_github.result()

        result_data = ExtendedOSINTResult(
            domain=target_domain,
            ct_subdomains=ct_subdomains,
            tls_audit=tls_data,
            shodan_hosts=shodan_hosts,
            github_leaks=github_leaks
        )

    # Calculate Risk
    risk = calculate_risk_score(result_data)

    col1, col2 = st.columns([1, 2])
    with col1:
        st.metric("Attack Surface Risk Score", f"{risk.score} / 100", delta=risk.severity, delta_color="inverse")
    with col2:
        st.markdown("**Calculated Risk Factors:**")
        for factor in risk.factors:
            st.markdown(f"• {factor}")

    st.divider()

    # Telemetry Navigation Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🌐 CT Subdomains", 
        "🔒 TLS Audit", 
        "📡 Shodan Passive", 
        "💻 GitHub Leaks", 
        "🧠 AI Threat Briefing",
        "📥 STIX & Exports"
    ])

    with tab1:
        st.subheader("Certificate Transparency Subdomains")
        if ct_err:
            st.warning(ct_err)
        if ct_subdomains:
            st.dataframe(ct_subdomains, column_config={"value": "Discovered Subdomain"}, use_container_width=True)
        else:
            st.info("No subdomains discovered in Certificate Transparency logs.")

    with tab2:
        st.subheader("Endpoint TLS/SSL Security Posture")
        if tls_err:
            st.error(tls_err)
        elif tls_data:
            st.write(f"**Issuer:** {tls_data.issuer}")
            st.write(f"**Valid Until:** {tls_data.expiration_date} ({tls_data.days_left} days remaining)")
            st.write(f"**TLS Cipher/Version:** {tls_data.cipher_version}")
            if tls_data.is_expired:
                st.error("⚠️ Certificate is EXPIRED!")
            else:
                st.success("✅ Certificate is valid.")
            
            with st.expander("Subject Alternative Names (SANs)"):
                st.write(tls_data.sans)

    with tab3:
        st.subheader("Shodan Passive Host Search")
        if shodan_err:
            st.warning(shodan_err)
        if shodan_hosts:
            for host in shodan_hosts:
                st.markdown(f"**IP:** `{host.ip}` | **Org:** {host.org}")
                st.markdown(f"- **Open Ports:** {host.ports}")
                st.markdown(f"- **Hostnames:** {', '.join(host.hostnames) if host.hostnames else 'N/A'}")
                st.markdown("---")
        else:
            st.info("No exposed endpoints found on Shodan.")

    with tab4:
        st.subheader("Public GitHub Repository Leaks")
        if github_err:
            st.warning(github_err)
        if github_leaks:
            st.dataframe(github_leaks, use_container_width=True)
        else:
            st.info("No sensitive configuration or credential leaks detected.")

    with tab5:
        st.subheader("Executive Threat Briefing & MITRE ATT&CK Mapping")
        with st.spinner("AWS Bedrock synthesizing telemetry..."):
            st.write_stream(generate_mitre_briefing(result_data))

    with tab6:
        st.subheader("Threat Intelligence Export Hub")
        st.markdown("Export gathered attack surface telemetry into standard STIX 2.1 or JSON formats for ingestion into SIEM, SOAR, or TIP platforms.")
        
        stix_data = generate_stix_bundle(result_data)
        json_data = generate_json_export(result_data)

        col_a, col_b = st.columns(2)
        with col_a:
            st.download_button(
                label="📦 Download STIX 2.1 Bundle (JSON)",
                data=stix_data,
                file_name=f"{target_domain}_stix_2.1.json",
                mime="application/json"
            )
        with col_b:
            st.download_button(
                label="📄 Download Raw OSINT Telemetry (JSON)",
                data=json_data,
                file_name=f"{target_domain}_osint_export.json",
                mime="application/json"
            )

        st.markdown("---")
        st.subheader("STIX 2.1 Bundle Preview")
        st.json(stix_data, expanded=False)
