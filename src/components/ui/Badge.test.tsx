import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { EncryptedChip, FrameKindChip, ProtocolChip, SeverityBadge, StatusChip } from "./Badge";

describe("semantic chips", () => {
  it("maps every severity to its colour class", () => {
    render(
      <div>
        <SeverityBadge severity="critical" />
        <SeverityBadge severity="high" />
        <SeverityBadge severity="medium" />
        <SeverityBadge severity="low" />
        <SeverityBadge severity="info" />
      </div>,
    );
    expect(screen.getByText("Critical")).toHaveClass("chip", "chip--critical");
    expect(screen.getByText("High")).toHaveClass("chip--high");
    expect(screen.getByText("Medium")).toHaveClass("chip--medium");
    expect(screen.getByText("Low")).toHaveClass("chip--low");
    expect(screen.getByText("Info")).toHaveClass("chip--info");
  });

  it("maps protocols to their colour class", () => {
    render(
      <div>
        <ProtocolChip protocol="TCP" />
        <ProtocolChip protocol="UDP" />
        <ProtocolChip protocol="DNS" />
        <ProtocolChip protocol="HTTP" />
        <ProtocolChip protocol="TLS" />
        <ProtocolChip protocol="ICMP" />
        <ProtocolChip protocol="Ethernet" />
        <ProtocolChip protocol="IPv4" />
        <ProtocolChip protocol="ssh" />
      </div>,
    );
    expect(screen.getByText("TCP")).toHaveClass("chip--tcp");
    expect(screen.getByText("UDP")).toHaveClass("chip--udp");
    expect(screen.getByText("DNS")).toHaveClass("chip--dns");
    expect(screen.getByText("HTTP")).toHaveClass("chip--http");
    expect(screen.getByText("TLS")).toHaveClass("chip--tls");
    expect(screen.getByText("ICMP")).toHaveClass("chip--icmp");
    expect(screen.getByText("ETHERNET")).toHaveClass("chip--eth");
    expect(screen.getByText("IPV4")).toHaveClass("chip--ip");
    expect(screen.getByText("SSH")).toHaveClass("chip--other");
  });

  it("renders frame-kind, encrypted and status chips", () => {
    render(
      <div>
        <FrameKindChip frameKind="management" />
        <FrameKindChip frameKind="control" />
        <FrameKindChip frameKind="data" />
        <EncryptedChip encrypted />
        <EncryptedChip encrypted={false} />
        <StatusChip status="investigating" />
        <StatusChip status="resolved" />
      </div>,
    );
    expect(screen.getByText("management")).toHaveClass("chip--management");
    expect(screen.getByText("control")).toHaveClass("chip--control");
    expect(screen.getByText("data")).toHaveClass("chip--data");
    expect(screen.getByText("Encrypted")).toHaveClass("chip--encrypted");
    expect(screen.getByText("investigating")).toHaveClass("chip--status-investigating");
    expect(screen.getByText("resolved")).toHaveClass("chip--status-resolved");
    expect(screen.queryByText("Encrypted")).toBeInTheDocument();
  });
});
