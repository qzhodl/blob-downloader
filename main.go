package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

var (
	rpcURL       *string
	blobNum      *int
	privateKey   *string
	contractAddr *string
	callData     *string
	fromBlock    *int
	toBlock      *int
)

var UploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a batch of blobs",
	Run:   runUpload,
}

var DownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download a batch of blobs",
	Run:   runDownload,
}

var GenBlobsCmd = &cobra.Command{
	Use:   "gen_blobs",
	Short: "Generate n blob files",
	Run:   runGenBlobs,
}

type Blobs struct {
	Data []BlobData `json:"data"`
}

type BlobData struct {
	BlockRoot       string `json:"block_root"`
	Index           string `json:"index"`
	Slot            string `json:"slot"`
	BlockParentRoot string `json:"block_parent_root"`
	ProposerIndex   string `json:"proposer_index"`
	Blob            string `json:"blob"`
	KZGCommitment   string `json:"kzg_commitment"`
	KZGProof        string `json:"kzg_proof"`
}

func init() {
	rpcURL = rootCmd.PersistentFlags().String("rpc_url", "http://65.109.50.145:8545", "rpc url")
	blobNum = rootCmd.PersistentFlags().Int("blob_num", 1, "blob number")
	privateKey = rootCmd.PersistentFlags().String("private_key", "", "private key")
	contractAddr = rootCmd.PersistentFlags().String("to_addr", "0x654FCe70AA989BC41dC50C4990555D0Ce9B3d6d7", "upload contract address")
	callData = rootCmd.PersistentFlags().String("call_data", "0x4581a9200000000000000000000000000000000000000000000000000000000000000abc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ec30", "upload call data")
	fromBlock = rootCmd.PersistentFlags().Int("from_block", 0, "from blob number")
	toBlock = rootCmd.PersistentFlags().Int("to_block", 0, "to block number")
}

func runUpload(cmd *cobra.Command, args []string) {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := 0; i < *blobNum; i++ {
		arguments := []string{}
		arguments = append(arguments, "tx")
		arguments = append(arguments, "--rpc-url")
		arguments = append(arguments, *rpcURL)
		arguments = append(arguments, "--blob-file")
		arguments = append(arguments, fmt.Sprintf("%s/file%d.txt", cwd, i))
		arguments = append(arguments, "--to")
		arguments = append(arguments, *contractAddr)
		arguments = append(arguments, "--private-key")
		arguments = append(arguments, *privateKey)
		arguments = append(arguments, "--gas-limit")
		arguments = append(arguments, "210000")
		arguments = append(arguments, "--chain-id")
		arguments = append(arguments, "42424243")
		arguments = append(arguments, "--priority-gas-price")
		arguments = append(arguments, "200000000")
		arguments = append(arguments, "--max-fee-per-data-gas")
		arguments = append(arguments, "300000000")
		arguments = append(arguments, "--calldata")
		arguments = append(arguments, *callData)

		command := exec.Command(fmt.Sprintf("%s/blob-utils", cwd), arguments...)
		output, err := command.Output()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Print(string(output))
		// time.Sleep(2 * time.Second)
	}
}

func runGenBlobs(cmd *cobra.Command, args []string) {
	// Set the random seed based on current time
	rand.Seed(time.Now().UnixNano())
	fileSize := 4096 * 31 // 31 * 4096 = 126k according to blob-utils

	for i := 0; i < *blobNum; i++ {
		fileName := fmt.Sprintf("file%d.txt", i)
		f, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating file:", err)
			return
		}
		defer f.Close()

		writer := bufio.NewWriter(f)
		for j := 0; j < fileSize; j++ {
			writer.WriteByte(byte(rand.Intn(94) + 33)) // ASCII printable characters range from 33 to 126
		}
		writer.Flush()
		fmt.Println("File", fileName, "has been generated.")
	}
}

func runDownload(cmd *cobra.Command, args []string) {
	// create a new Ethereum client
	client, err := ethclient.Dial(*rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	// define the contract address and event signature to watch for
	contractAddr := common.HexToAddress(*contractAddr)
	eventSig := []byte("PutBlob(uint256,uint256,bytes32)")
	topic := crypto.Keccak256Hash(eventSig)

	// create a new filter query
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddr},
		Topics: [][]common.Hash{
			{
				topic,
			},
		},
		FromBlock: big.NewInt(int64(*fromBlock)),
		ToBlock:   big.NewInt(int64(*toBlock)),
	}

	// retrieve past events that match the filter query
	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		log.Fatalf("Failed to retrieve past events: %v", err)
	}

	dl_blocks := []uint64{}

	for _, log := range logs {
		dl_blocks = append(dl_blocks, log.BlockNumber)
	}

	for i, block_num := range dl_blocks {
		url := fmt.Sprintf("http://65.109.50.145:8000/eth/v1/beacon/blobs/%d", block_num)
		resp, err := http.Get(url)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		var blobs Blobs
		err = json.NewDecoder(resp.Body).Decode(&blobs)
		if err != nil {
			fmt.Println("Error decoding response:", err)
			return
		}

		fmt.Println("Response:", blobs.Data[0].Slot)

		// decode hex string to bytes
		asciiBytes, err := hex.DecodeString(blobs.Data[0].Blob[2:])
		if err != nil {
			panic(err)
		}

		fileName := fmt.Sprintf("dl_file%d.txt", i)
		f, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating file:", err)
			return
		}
		defer f.Close()

		writer := bufio.NewWriter(f)
		writer.WriteString(string(asciiBytes))
		writer.Flush()
	}

	for i := range dl_blocks {
		same := compareTwoFiles(fmt.Sprintf("file%d.txt", i), fmt.Sprintf("dl_file%d.txt", i))
		if !same {
			fmt.Printf("%d blob is not same when comparing upload and download\n", i)
		} else {
			fmt.Printf("%d blob compare pass\n", i)
		}
	}
}

func compareTwoFiles(ul_file string, dl_file string) bool {
	f1, err := os.ReadFile(ul_file)
	if err != nil {
		fmt.Println(err)
		return false
	}

	f2, err := os.ReadFile(dl_file)
	if err != nil {
		fmt.Println(err)
		return false
	}
	fieldIndex := 0
	var equal bool
	for i := 0; i < len(f1); i += 31 {
		equal = bytes.Equal(f1[i:i+31], f2[fieldIndex*32:fieldIndex*32+31])
		if !equal {
			return false
		}
		fieldIndex++
	}

	return true
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "blob-downloader",
	Short: "Track the latest block and download blobs",
}

func init() {
	rootCmd.AddCommand(UploadCmd)
	rootCmd.AddCommand(DownloadCmd)
	rootCmd.AddCommand(GenBlobsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
