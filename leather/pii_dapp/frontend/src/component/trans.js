import React from "react";
import { openContractCall } from "@stacks/connect";
import { StacksTestnet } from "@stacks/network";
import { contractPrincipalCV } from "@stacks/transactions";
import { userSession } from "../userSession";
import { CONTRACT_ADDRESS, CONTRACT_NAME } from "../config";

export default function TransactionButton() {
  const handleTransaction = async () => {
    const network = new StacksTestnet();

    const options = {
      contractAddress: CONTRACT_ADDRESS,
      contractName: CONTRACT_NAME,
      functionName: "store-pii",   // <-- replace with your function
      functionArgs: [
        contractPrincipalCV(CONTRACT_ADDRESS, CONTRACT_NAME)
      ],
      network,
      appDetails: {
        name: "PII Registry",
        icon: window.location.origin + "/favicon.ico"
      },
      onFinish: (data) => {
        console.log("Transaction finished:", data);
        alert("Transaction sent! TxID: " + data.txId);
      },
    };

    await openContractCall(options);
  };

  return (
    <button
      onClick={handleTransaction}
      style={{ padding: "10px 20px", fontSize: "16px", marginTop: "20px" }}
    >
      Send Transaction
    </button>
  );
}
