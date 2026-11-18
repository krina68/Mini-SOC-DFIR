
import streamlit as st
import pandas as pd
import plotly.express as px
import hashlib

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
from collections import Counter, defaultdict
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from xml.sax.saxutils import escape

# ---------------- PAGE SETTINGS ----------------

st.set_page_config(
    page_title="Mini SOC-to-DFIR",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Mini SOC-to-DFIR")
st.caption("Network Security Monitoring | Investigation | Evidence Integrity")

# ---------------- SIDEBAR ----------------

st.sidebar.title("Investigation Panel")
st.sidebar.write("Upload a PCAP file to begin.")

uploaded_file = st.sidebar.file_uploader(
    "Upload Network Capture",
    type=["pcap", "pcapng"]
)

st.sidebar.info(
    "Supported formats: PCAP and PCAPNG"
)

st.sidebar.markdown("---")
st.sidebar.caption("Mini SOC-to-DFIR | Version 2")

# ---------------- MAIN PAGE ----------------

if uploaded_file is None:

    st.info("Please upload a PCAP file using the sidebar.")

    st.subheader("Application Modules")

    col1, col2, col3 = st.columns(3)

    col1.markdown("### 📡 Network Analysis")
    col1.write("Analyse packets, IP addresses, protocols and ports.")

    col2.markdown("### 🚨 Threat Detection")
    col2.write("Identify possible suspicious network activities.")

    col3.markdown("### 🔐 Evidence Integrity")
    col3.write("Calculate SHA-256 hashes for evidence verification.")

else:

    file_data = uploaded_file.getvalue()

    st.success(f"Uploaded successfully: {uploaded_file.name}")

    # ---------------- FILE INFORMATION ----------------

    file_hash = hashlib.sha256(file_data).hexdigest()

    st.header("1. Evidence Information")

    col1, col2 = st.columns(2)

    col1.metric("File Size", f"{len(file_data):,} bytes")
    col2.metric("File Format", uploaded_file.name.split(".")[-1].upper())

    st.write("**SHA-256 Hash**")
    st.code(file_hash)

    st.download_button(
        "Download SHA-256 Record",
        data=f"File: {uploaded_file.name}\nSHA-256: {file_hash}\n",
        file_name="evidence_hash.txt",
        mime="text/plain"
    )

    # ---------------- PACKET ANALYSIS ----------------

    try:
        with st.spinner("Analysing network packets..."):
            packets = rdpcap(BytesIO(file_data))

        total_packets = len(packets)

        if total_packets == 0:
            st.warning("The uploaded capture contains no packets.")
            st.stop()

        source_ips = Counter()
        destination_ips = Counter()
        destination_ports = Counter()

        network_protocols = Counter()
        transport_protocols = Counter()
        tcp_flags = Counter()

        syn_only = 0
        syn_ack = 0
        rst_count = 0
        fin_count = 0
        udp_count = 0
        icmp_count = 0
        tcp_count = 0
        arp_count = 0
        ip_count = 0

        scan_ports = defaultdict(set)
        scan_syn_count = Counter()
        packets_per_second = Counter()

        timestamps = []

        # ---------------- PROCESS PACKETS ----------------

        for packet in packets:

            timestamp = float(packet.time)
            timestamps.append(timestamp)

            if ARP in packet:
                arp_count += 1
                network_protocols["ARP"] += 1

            if IP in packet:
                ip_count += 1

                src = packet[IP].src
                dst = packet[IP].dst

                source_ips[src] += 1
                destination_ips[dst] += 1

                network_protocols["IPv4"] += 1

                if TCP in packet:

                    tcp_count += 1
                    transport_protocols["TCP"] += 1

                    tcp = packet[TCP]
                    port = int(tcp.dport)
                    flags = int(tcp.flags)

                    destination_ports[port] += 1

                    # Individual TCP flag counts
                    for bit, name in [
                        (0x01, "FIN"),
                        (0x02, "SYN"),
                        (0x04, "RST"),
                        (0x08, "PSH"),
                        (0x10, "ACK"),
                        (0x20, "URG"),
                        (0x40, "ECE"),
                        (0x80, "CWR")
                    ]:
                        if flags & bit:
                            tcp_flags[name] += 1

                    if flags & 0x12 == 0x02:
                        syn_only += 1

                        scan_ports[(src, dst)].add(port)
                        scan_syn_count[(src, dst)] += 1

                    if flags & 0x12 == 0x12:
                        syn_ack += 1

                    if flags & 0x04:
                        rst_count += 1

                    if flags & 0x01:
                        fin_count += 1

                elif UDP in packet:
                    udp_count += 1
                    transport_protocols["UDP"] += 1

                elif ICMP in packet:
                    icmp_count += 1
                    transport_protocols["ICMP"] += 1

            second = int(timestamp - min(timestamps))
            packets_per_second[second] += 1

        # ---------------- SUMMARY ----------------

        capture_duration = max(timestamps) - min(timestamps)

        unique_ports = len(destination_ports)

        st.header("2. Network Overview")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Total Packets", f"{total_packets:,}")
        c2.metric("TCP Packets", f"{tcp_count:,}")
        c3.metric("UDP Packets", f"{udp_count:,}")
        c4.metric("Unique Destination Ports", f"{unique_ports:,}")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("SYN-only Packets", f"{syn_only:,}")
        c2.metric("SYN-ACK Packets", f"{syn_ack:,}")
        c3.metric("RST Packets", f"{rst_count:,}")
        c4.metric("Capture Duration", f"{capture_duration:.2f} sec")

        # ---------------- TABS ----------------

        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Traffic Dashboard",
            "🔎 Network Investigation",
            "🚨 Security Alerts",
            "🔐 Evidence Integrity"
        ])

        # ---------------- TAB 1 ----------------

        with tab1:

            st.subheader("Protocol Distribution")

            protocol_df = pd.DataFrame([
                {"Protocol": "ARP", "Packets": arp_count},
                {"Protocol": "IPv4", "Packets": ip_count},
                {"Protocol": "TCP", "Packets": tcp_count},
                {"Protocol": "UDP", "Packets": udp_count},
                {"Protocol": "ICMP", "Packets": icmp_count}
            ])

            protocol_df = protocol_df[protocol_df["Packets"] > 0]

            fig = px.bar(
                protocol_df,
                x="Protocol",
                y="Packets",
                color="Protocol",
                title="Packet Counts by Protocol Layer"
            )

            st.plotly_chart(fig, use_container_width=True)

            st.caption(
                "IPv4 is a network-layer count. TCP, UDP and ICMP are "
                "transport/network-layer protocol counts, so these "
                "categories are not mutually exclusive."
            )

            st.subheader("Network Traffic Over Time")

            timing_df = pd.DataFrame(
                list(packets_per_second.items()),
                columns=["Second", "Packets"]
            ).sort_values("Second")

            fig = px.line(
                timing_df,
                x="Second",
                y="Packets",
                markers=True,
                title="Packets per Second"
            )

            st.plotly_chart(fig, use_container_width=True)

        # ---------------- TAB 2 ----------------

        with tab2:

            st.subheader("Source IP Addresses")

            source_df = pd.DataFrame(
                source_ips.most_common(20),
                columns=["Source IP", "Packet Count"]
            )

            st.dataframe(source_df, use_container_width=True)

            st.subheader("Destination IP Addresses")

            destination_df = pd.DataFrame(
                destination_ips.most_common(20),
                columns=["Destination IP", "Packet Count"]
            )

            st.dataframe(destination_df, use_container_width=True)

            st.subheader("Destination Port Analysis")

            port_df = pd.DataFrame(
                destination_ports.most_common(),
                columns=["Destination Port", "Packet Count"]
            )

            st.dataframe(
                port_df.head(30),
                use_container_width=True
            )

            st.download_button(
                "Download Destination Ports CSV",
                data=port_df.to_csv(index=False),
                file_name="destination_ports.csv",
                mime="text/csv"
            )

            st.subheader("TCP Flag Analysis")

            flag_df = pd.DataFrame(
                tcp_flags.items(),
                columns=["TCP Flag", "Count"]
            )

            st.dataframe(flag_df, use_container_width=True)

            st.write("SYN-only packets:", syn_only)
            st.write("SYN-ACK packets:", syn_ack)
            st.write("RST packets:", rst_count)
            st.write("FIN packets:", fin_count)

        # ---------------- TAB 3 ----------------

        with tab3:

            st.subheader("Suspicious Activity Detection")

            threshold = st.slider(
                "Minimum unique destination ports for a possible scan alert",
                min_value=10,
                max_value=1000,
                value=100,
                step=10
            )

            alerts = []

            for (src, dst), ports in scan_ports.items():

                if len(ports) >= threshold:

                    alerts.append({
                        "Source IP": src,
                        "Destination IP": dst,
                        "Unique Ports": len(ports),
                        "SYN-only Packets": scan_syn_count[(src, dst)],
                        "Severity": "High",
                        "Detection": "Possible TCP SYN port scan"
                    })

            if alerts:

                st.error(f"{len(alerts)} possible scanning alert(s) detected.")

                alert_df = pd.DataFrame(alerts)

                st.dataframe(alert_df, use_container_width=True)

                st.warning(
                    "This is a traffic-pattern alert, not proof of malicious intent."
                )

                st.write("**Supporting evidence:**")

                for alert in alerts:
                    st.write(
                        f"- {alert['Source IP']} sent "
                        f"{alert['SYN-only Packets']} SYN-only packets to "
                        f"{alert['Destination IP']} across "
                        f"{alert['Unique Ports']} unique destination ports."
                    )

                st.download_button(
                    "Download Security Alerts CSV",
                    data=alert_df.to_csv(index=False),
                    file_name="security_alerts.csv",
                    mime="text/csv"
                )

            else:

                st.success(
                    "No possible port-scanning pattern matched the selected threshold."
                )

            st.subheader("Detection Method")

            st.write(
                "The application groups TCP SYN-only packets by source and "
                "destination IP address. It counts the unique destination "
                "ports and compares the count with the selected threshold."
            )

        # ---------------- TAB 4 ----------------

        with tab4:

            st.subheader("Evidence Integrity Verification")

            st.write("**Evidence File:**", uploaded_file.name)
            st.write("**SHA-256 Hash:**")
            st.code(file_hash)

            st.success(
                "SHA-256 hash calculated successfully for the uploaded file."
            )

            st.write(
                "Save this hash as the original evidence reference. "
                "A later hash can be compared with it to check whether "
                "the file has changed."
            )

            st.download_button(
                "Download Evidence Record",
                data=(
                    f"Evidence File: {uploaded_file.name}\n"
                    f"File Size: {len(file_data)} bytes\n"
                    f"SHA-256: {file_hash}\n"
                ),
                file_name="evidence_record.txt",
                mime="text/plain"
            )

        # ---------------- EXPORT SUMMARY ----------------

        # ---------------- PDF INVESTIGATION REPORT ----------------

        st.markdown("---")
        st.header("5. Automated Investigation Report")

        def create_pdf_report():

            pdf_buffer = BytesIO()

            document = SimpleDocTemplate(
                pdf_buffer,
                pagesize=A4,
                rightMargin=18 * mm,
                leftMargin=18 * mm,
                topMargin=18 * mm,
                bottomMargin=18 * mm
            )

            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph(
                "MINI SOC-to-DFIR INVESTIGATION REPORT",
                styles["Title"]
            ))

            story.append(Spacer(1, 8))

            story.append(Paragraph(
                "Network Traffic Analysis and Evidence Integrity",
                styles["Heading2"]
            ))

            story.append(Spacer(1, 12))

            # Evidence information
            story.append(Paragraph(
                "1. Evidence Information",
                styles["Heading2"]
            ))

            evidence_data = [
                ["Field", "Details"],
                ["PCAP File", escape(uploaded_file.name)],
                ["File Size", f"{len(file_data):,} bytes"],
                ["Total Packets", str(total_packets)],
                ["SHA-256", file_hash]
            ]

            evidence_table = Table(
                evidence_data,
                colWidths=[38 * mm, 125 * mm]
            )

            evidence_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7)
            ]))

            story.append(evidence_table)
            story.append(Spacer(1, 15))

            # Network analysis
            story.append(Paragraph(
                "2. Network Analysis",
                styles["Heading2"]
            ))

            network_data = [
                ["Metric", "Observed Value"],
                ["IPv4 Packets", str(ip_count)],
                ["ARP Packets", str(arp_count)],
                ["TCP Packets", str(tcp_count)],
                ["UDP Packets", str(udp_count)],
                ["ICMP Packets", str(icmp_count)],
                ["SYN-only Packets", str(syn_only)],
                ["SYN-ACK Packets", str(syn_ack)],
                ["RST Packets", str(rst_count)],
                ["Unique Destination Ports", str(unique_ports)],
                ["Capture Duration", f"{capture_duration:.2f} seconds"]
            ]

            network_table = Table(network_data, colWidths=[75 * mm, 88 * mm])

            network_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6)
            ]))

            story.append(network_table)
            story.append(Spacer(1, 15))

            # Source IP addresses
            story.append(Paragraph(
                "3. Source IP Address Analysis",
                styles["Heading2"]
            ))

            source_data = [["Source IP", "Packet Count"]]

            for ip, count in source_ips.most_common(10):
                source_data.append([ip, str(count)])

            source_table = Table(source_data, colWidths=[80 * mm, 83 * mm])

            source_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9)
            ]))

            story.append(source_table)
            story.append(Spacer(1, 15))

            # Destination ports
            story.append(Paragraph(
                "4. Destination Port Analysis",
                styles["Heading2"]
            ))

            port_data = [["Destination Port", "Packet Count"]]

            for port, count in destination_ports.most_common(20):
                port_data.append([str(port), str(count)])

            port_table = Table(port_data, colWidths=[80 * mm, 83 * mm])

            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9)
            ]))

            story.append(port_table)
            story.append(Spacer(1, 15))

            # Security alerts
            story.append(Paragraph(
                "5. Security Findings",
                styles["Heading2"]
            ))

            if alerts:

                for alert in alerts:

                    finding = (
                        f"Detection: {alert['Detection']}<br/>"
                        f"Severity: {alert['Severity']}<br/>"
                        f"Source IP: {alert['Source IP']}<br/>"
                        f"Destination IP: {alert['Destination IP']}<br/>"
                        f"Unique Ports: {alert['Unique Ports']}<br/>"
                        f"SYN-only Packets: {alert['SYN-only Packets']}"
                    )

                    story.append(Paragraph(finding, styles["BodyText"]))
                    story.append(Spacer(1, 8))

            else:

                story.append(Paragraph(
                    "No possible port-scanning pattern matched the selected threshold.",
                    styles["BodyText"]
                ))

            story.append(Spacer(1, 12))

            story.append(Paragraph(
                "6. Investigation Conclusion and Recommendations",
                styles["Heading2"]
            ))

            conclusion = (
                f"The analysis processed {total_packets} packets. "
                f"It identified {unique_ports} unique TCP destination ports "
                f"and {syn_only} SYN-only packets. "
            )

            if alerts:
                conclusion += (
                    "A possible TCP SYN port-scanning pattern was detected. "
                    "Further investigation and validation are recommended."
                )
            else:
                conclusion += (
                    "No port-scanning pattern matched the configured detection "
                    "threshold. This does not establish that the traffic was safe."
                )

            story.append(Paragraph(conclusion, styles["BodyText"]))
            story.append(Spacer(1, 8))

            story.append(Paragraph(
                "Recommendations: Review the source and destination systems, "
                "inspect relevant packet evidence in Wireshark, and compare "
                "the evidence hash with a separately preserved reference hash.",
                styles["BodyText"]
            ))

            story.append(Spacer(1, 15))

            story.append(Paragraph(
                "Report generated automatically by the Mini SOC-to-DFIR application.",
                styles["Italic"]
            ))

            document.build(story)

            pdf_buffer.seek(0)

            return pdf_buffer.getvalue()

        pdf_data = create_pdf_report()

        st.download_button(
            "Download Investigation Report (PDF)",
            data=pdf_data,
            file_name="Mini_SOC_DFIR_Investigation_Report.pdf",
            mime="application/pdf"
        )


        st.markdown("---")

        st.subheader("Investigation Summary")

        summary = f"""
MINI SOC-TO-DFIR INVESTIGATION SUMMARY

File: {uploaded_file.name}
Total Packets: {total_packets}
IPv4 Packets: {ip_count}
ARP Packets: {arp_count}
TCP Packets: {tcp_count}
UDP Packets: {udp_count}
ICMP Packets: {icmp_count}

SYN-only Packets: {syn_only}
SYN-ACK Packets: {syn_ack}
RST Packets: {rst_count}

Unique Destination Ports: {unique_ports}
Capture Duration: {capture_duration:.2f} seconds

SHA-256: {file_hash}

This summary is generated automatically by the application.
"""

        st.download_button(
            "Download Investigation Summary",
            data=summary,
            file_name="investigation_summary.txt",
            mime="text/plain"
        )

        st.success("Network analysis completed successfully!")

    except Exception as error:

        st.error("The uploaded file could not be analysed.")

        st.write("Error details:", str(error))

        st.info(
            "Please check whether the uploaded PCAP file is valid "
            "and supported."
        )

st.markdown("---")
st.caption("Mini SOC-to-DFIR | Network Investigation and Evidence Integrity")
