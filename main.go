package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/spf13/cobra"
)

var (
	rpcURL *string
)

var UploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a batch of blobs",
	Run:   runUpload,
}

func init() {
	rpcURL = rootCmd.PersistentFlags().String("rpc_url", "", "rpc url")
}

func runUpload(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	txHash := common.HexToHash("0x9f2cb18461089cf87f92f3f12dfe04676f5405c50ade54597c4f69d357394956")
	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}

	// Get the block number from the receipt
	blockNumber := receipt.BlockNumber
	log.Printf("Block number of the tx is %d", blockNumber)

}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "blob-downloader",
	Short: "Track the latest block and download blobs",
}

func init() {
	rootCmd.AddCommand(UploadCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
