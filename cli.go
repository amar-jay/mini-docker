package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"github.com/mgutz/ansi"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/urfave/cli/v3"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func red(format string, args ...any) error {
	return fmt.Errorf(ansi.Color(fmt.Sprintf(format, args...), "red+dbi") + "\n")
}
func green(format string, args ...any) string {
	return fmt.Sprintf(ansi.Color(fmt.Sprintf(format, args...), "green+hb") + "\n")
}
func yellow(format string, args ...any) string {
	return fmt.Sprintf(ansi.Color(fmt.Sprintf(format, args...), "yellow+hb") + "\n")
}

func createDirs(dirs []string) error {

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return cli.Exit(red("Failed to create necessary directories: %v", err), 1)
		}
	}
	return nil
}

func setupBridge() error {
	if links, err := netlink.LinkList(); err == nil {
		for _, link := range links {
			if link.Type() == "bridge" && link.Attrs().Name == SYMBOLON_BRIDGE_NAME {
				return nil
			}
		}
	} else {
		return cli.Exit(red("unable to get list of links: %v", err), 1)
	}

	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = SYMBOLON_BRIDGE_NAME
	symbolonBridge := &netlink.Bridge{LinkAttrs: linkAttrs}
	if err := netlink.LinkAdd(symbolonBridge); err != nil {
		return cli.Exit(red("Failed to set up the network bridge: %v", err), 1)
	}
	addr, _ := netlink.ParseAddr(SYMBOLON_NETWORK_ADDRESS)
	netlink.AddrAdd(symbolonBridge, addr)
	netlink.LinkSetUp(symbolonBridge)
	return nil
}

func getNameAndTag(src string) (string, string) {
	s := strings.Split(src, ":")
	if len(s) > 1 {
		return s[0], s[1]
	}
	return s[0], "latest"
}

type manifest []struct {
	Config   string
	RepoTags []string
	Layers   []string
}

type imageConfigDetails struct {
	Env []string `json:"Env"`
	Cmd []string `json:"Cmd"`
}
type imageConfig struct {
	Config imageConfigDetails `json:"config"`
}

type entries map[string]string
type metadata map[string]entries

func parseMetadata(idb *metadata) error {
	imagesDBPath := filepath.Join(SYMBOLON_IMAGES_PATH, "images.json")

	if _, err := os.Stat(imagesDBPath); os.IsNotExist(err) {
		// Create an empty DB file if it doesn't exist
		if err := os.WriteFile(imagesDBPath, []byte("{}"), 0644); err != nil {
			return cli.Exit(red("Failed to create images DB: %v", err), 1)
		}
	}

	data, err := os.ReadFile(imagesDBPath)
	if err != nil {
		return cli.Exit(red("Failed to read images DB: %v", err), 1)
	}

	if err = json.Unmarshal(data, idb); err != nil {
		return cli.Exit(red("Failed to parse images DB: %v", err), 1)
	}
	return nil
}

func fetchImageHash(imgName string, tagName string) string {
	idb := metadata{}
	parseMetadata(&idb)
	for k, v := range idb {
		if k == imgName {
			for k, v := range v {
				if k == tagName {
					return v // This is the image SHA256 hash
				}
			}
		}
	}
	return ""
}

func fetchImageNameAndTag(imageHash string) (name string, tag string) {
	idb := metadata{}
	parseMetadata(&idb)
	for imgName, avlImages := range idb {
		for imgTag, imgHash := range avlImages {
			if imgHash == imageHash {
				return imgName, imgTag
			}
		}
	}
	return
}
func marshalMetadata(idb metadata) error {
	data, err := json.MarshalIndent(idb, "", "  ")
	if err != nil {
		return red("Failed to marshal images metadata: %v", err)
	}

	imagesDBPath := filepath.Join(SYMBOLON_IMAGES_PATH, "images.json")
	if err := os.WriteFile(imagesDBPath, data, 0644); err != nil {
		return red("Failed to write images DB: %v", err)
	}
	return nil
}

func storeMetadata(image string, tag string, imageHash string) error {
	idb := metadata{}
	ientry := entries{}
	parseMetadata(&idb)
	if idb[image] != nil {
		ientry = idb[image]
	}
	ientry[tag] = imageHash
	idb[image] = ientry

	if err := marshalMetadata(idb); err != nil {
		return err
	}
	return nil
}

func parseManifest(manifestPath string, mani *manifest) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, mani); err != nil {
		return err
	}
	return nil
}
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func downloadImage(img v1.Image, imageHash, src string) error {
	tempDir := filepath.Join(SYMBOLON_TMP_PATH, imageHash)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return red("Failed to create temporary directory %s: %v", tempDir, err)
	}
	tarPath := filepath.Join(tempDir, "package.tar")
	if err := crane.SaveLegacy(img, src, tarPath); err != nil {
		return red("Failed to save image %s: %v", src, err)
	}
	log.Printf("Successfully downloaded image %q to %s", src, tarPath)
	return nil
}

func parseContainerConfig(imageShaHex string) imageConfig {
	imagesConfigPath := filepath.Join(SYMBOLON_IMAGES_PATH, imageShaHex+".json")
	data, err := os.ReadFile(imagesConfigPath)
	if err != nil {
		log.Fatalf("Could not read image config file")
	}
	imgConfig := imageConfig{}
	if err := json.Unmarshal(data, &imgConfig); err != nil {
		log.Fatalf("Unable to parse image config data!")
	}
	return imgConfig
}

func untarFile(imageHash string, fullImageHex v1.Hash) error {
	tempDir := filepath.Join(SYMBOLON_TMP_PATH, imageHash)
	tarPath := filepath.Join(tempDir, "package.tar")

	if err := untar(tarPath, tempDir); err != nil {
		return red("Failed to extract tarball %q: %v", tarPath, err)
	}

	manifestPath := filepath.Join(tempDir, "manifest.json")
	// config is a sha256:<hash> string, we need to extract the hash
	configName := fullImageHex.Algorithm + ":" + fullImageHex.Hex
	configPath := filepath.Join(tempDir, configName)

	var mani manifest
	if err := parseManifest(manifestPath, &mani); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	if len(mani) == 0 || len(mani[0].Layers) == 0 {
		return fmt.Errorf("no layers found in manifest")
	}
	if len(mani) > 1 {
		return fmt.Errorf("multiple manifests found; only one is supported")
	}

	imageDir := filepath.Join(SYMBOLON_IMAGES_PATH, imageHash)
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return fmt.Errorf("creating image directory: %w", err)
	}

	for _, layer := range mani[0].Layers {
		layerID := layer[:12]
		layerDir := filepath.Join(imageDir, layerID, "fs")
		layerTar := filepath.Join(tempDir, layer)

		log.Printf("Unpacking layer to: %s", layerDir)

		if err := os.MkdirAll(layerDir, 0755); err != nil {
			return fmt.Errorf("creating layer directory %s: %w", layerDir, err)
		}
		if err := untar(layerTar, layerDir); err != nil {
			return fmt.Errorf("untarring layer %s: %w", layerTar, err)
		}
	}

	_manifestPath := filepath.Join(SYMBOLON_IMAGES_PATH, imageHash, "manifest.json")
	_configPath := filepath.Join(SYMBOLON_IMAGES_PATH, imageHash+".json")
	if err := copyFile(manifestPath, _manifestPath); err != nil {
		return fmt.Errorf("copying manifest: %w", err)
	}
	if err := copyFile(configPath, _configPath); err != nil {
		return fmt.Errorf("copying config: %w", err)
	}
	return nil
}

func deleteTempImageFiles(imageShaHash string) error {
	tmpPath := filepath.Join(SYMBOLON_TMP_PATH, imageShaHash)

	if err := os.RemoveAll(tmpPath); err != nil {
		return red("failed to remove temporary image files at %q: %w", tmpPath, err)
	}

	log.Printf("Cleaned up temporary files: %s", tmpPath)
	return nil
}

func downloadImageIfRequired(src string) (string, error) {
	imgName, tagName := getNameAndTag(src)
	if imageHash := fetchImageHash(imgName, tagName); len(imageHash) > 0 {
		return imageHash, nil
	} else {
		/* setup the image we want to pull */
		log.Printf("Downloading metadata for %s:%s, please wait...", imgName, tagName)
		img, err := crane.Pull(strings.Join([]string{imgName, tagName}, ":"))
		if err != nil {
			return "", cli.Exit(red("Failed to pull image %s:%s: %v", imgName, tagName, err), 1)
		}

		manifest, _ := img.Manifest()
		imageHash = manifest.Config.Digest.Hex[:12]
		log.Printf("imageHash: %v\n", imageHash)
		log.Println("Checking if image exists under another name...")

		/* Identify cases where ubuntu:latest could be the same as ubuntu:20.04*/
		altImgName, altImgTag := fetchImageNameAndTag(imageHash)
		if len(altImgName) > 0 && len(altImgTag) > 0 {
			log.Printf("The image you requested %s:%s is the same as %s:%s\n",
				imgName, tagName, altImgName, altImgTag)
			if err = storeMetadata(imgName, tagName, imageHash); err != nil {
				return "", err
			}
			return imageHash, nil
		} else {
			log.Println("Image doesn't exist. Downloading...")
			if err := downloadImage(img, imageHash, src); err != nil {
				return "", err
			}
			if err = untarFile(imageHash, manifest.Config.Digest); err != nil {
				return "", err
			}
			if err = storeMetadata(imgName, tagName, imageHash); err != nil {
				return "", err
			}
			if err = deleteTempImageFiles(imageHash); err != nil {
				return "", err
			}
			return imageHash, nil
		}
	}
}

func createContainerDirs(containerID string) error {
	homeDir := filepath.Join(SYMBOLON_CONTAINERS_PATH, containerID)
	dirs := []string{
		homeDir,
		homeDir + "/fs",
		homeDir + "/fs/mnt",
		homeDir + "/fs/upperdir",
		homeDir + "/fs/workdir",
	}
	if err := createDirs(dirs); err != nil {
		return red("Failed to create container directories: %v", err)
	}
	return nil
}

func mountOverlayFileSystem(containerID, imageShaHex string) error {
	// Parse manifest once
	var mani manifest
	imageManifest := filepath.Join(SYMBOLON_IMAGES_PATH, imageShaHex, "manifest.json")
	if err := parseManifest(imageManifest, &mani); err != nil {
		return red("Failed to parse manifest: %v", err)
	}
	if len(mani) == 0 || len(mani[0].Layers) == 0 {
		return red("manifest has no layers")
	}
	if len(mani) > 1 {
		return red("multi-manifest images are not supported")
	}

	// Pre-allocate and build reverse layer list
	layers := mani[0].Layers
	layerCount := len(layers)
	srcLayers := make([]string, layerCount)
	imageBase := filepath.Join(SYMBOLON_IMAGES_PATH, imageShaHex)

	for i := range layerCount {
		layerID := layers[layerCount-1-i][:12]
		srcLayers[i] = filepath.Join(imageBase, layerID, "fs")
	}

	// Compose overlay mount options
	containerHome := filepath.Join(SYMBOLON_CONTAINERS_PATH, containerID, "fs")
	mntOpts := strings.Builder{}
	mntOpts.Grow(256 + 32*layerCount) // avoid reallocations

	mntOpts.WriteString("lowerdir=")
	mntOpts.WriteString(strings.Join(srcLayers, ":"))
	mntOpts.WriteString(",upperdir=")
	mntOpts.WriteString(filepath.Join(containerHome, "upperdir"))
	mntOpts.WriteString(",workdir=")
	mntOpts.WriteString(filepath.Join(containerHome, "workdir"))

	mountPoint := filepath.Join(containerHome, "mnt")
	if err := unix.Mount("none", mountPoint, "overlay", 0, mntOpts.String()); err != nil {
		return red("Failed to mount overlay filesystem: %v", err)
	}
	return nil
}

func prepareAndExecuteContainer(mem, swap, pids int, cpus float64,
	containerID, imageShaHex string, cmdArgs []string) {

	fmt.Print(green("Preparing to run container %s with image %s", containerID, imageShaHex))
	fmt.Print(green("Container ID: %s", containerID))
	fmt.Print(green("Image SHA256: %s", imageShaHex))
	fmt.Print(green("Command arguments: %s", strings.Join(cmdArgs, " ")))
	// Step 1: Setup network namespace
	/*
		if err := runSetupStep("setup-netns", containerID); err != nil {
			log.Print(yellow("Failed to setup network namespace for container %s: %v", containerID, err))
			//log.Fatalf("setup-netns failed: %v", err)
		}

		fmt.Print(green("Network namespace setup for container %s completed", containerID))
		// Step 2: Setup veth pair inside netns
		if err := runSetupStep("setup-veth", containerID); err != nil {
			log.Print(yellow("setup-veth failed: %v", err))
		}
	*/

	// Step 3: Build runtime options
	var opts []string
	if mem > 0 {
		opts = append(opts, "--mem="+strconv.Itoa(mem))
	}
	if swap >= 0 {
		opts = append(opts, "--swap="+strconv.Itoa(swap))
	}
	if pids > 0 {
		opts = append(opts, "--pids="+strconv.Itoa(pids))
	}
	if cpus > 0 {
		opts = append(opts, "--cpus="+strconv.FormatFloat(cpus, 'f', 1, 64))
	}
	opts = append(opts, "--image="+imageShaHex)
	opts = append(opts, "--container_id="+containerID)

	// Step 4: Build full argument list for child
	args := append([]string{"setup", "child-mode"}, opts...)
	args = append(args, cmdArgs...)

	// Step 5: Spawn containerized process in new namespaces
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWPID |
			unix.CLONE_NEWNS |
			unix.CLONE_NEWUTS |
			unix.CLONE_NEWIPC,
	}

	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to run container child: %v", err)
	}
}

func setupContainer(image, options string) error {
	id := uuid.NewString()
	imageHash, err := downloadImageIfRequired(image)
	if err != nil {
		return cli.Exit(err, 1)
	}
	if err := createContainerDirs(id); err != nil {
		return cli.Exit(err, 1)
	}
	if err := mountOverlayFileSystem(id, imageHash); err != nil {
		return cli.Exit(err, 1)
	}
	fmt.Printf("Container %s is being set up with image %s\n", id, image)
	if err := setupVirtualEthOnHost(id); err != nil {
		log.Fatalf("Unable to setup Veth0 on host: %v", err)
	}
	prepareAndExecuteContainer(-1, -1, -1, -1, id, imageHash, strings.Split(options, " "))
	fmt.Printf("Container %s is running with image %s\n", id, image)
	return nil
}

func setupNewNetworkNamespace(containerID string) error {
	_ = createDirs([]string{SYMBOLON_NETNS_PATH})
	nsMount := filepath.Join(SYMBOLON_NETNS_PATH, containerID)
	if _, err := unix.Open(nsMount, unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL, 0644); err != nil {
		return cli.Exit(red("Unable to open bind mount file: :%v\n", err), 1)
	}

	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY, 0)
	defer unix.Close(fd)
	if err != nil {
		return cli.Exit(red("Unable to open: %v\n", err), 1)
	}

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return cli.Exit(red("Unshare system call failed: %v\n", err), 1)
	}
	if err := unix.Mount("/proc/self/ns/net", nsMount, "bind", unix.MS_BIND, ""); err != nil {
		return cli.Exit(red("Mount system call failed: %v\n", err), 1)
	}
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return cli.Exit(red("Setns system call failed: %v\n", err), 1)
	}
	return nil
}

func createCGroups(containerID string, createCGroupDirs bool) error {
	cgroups := []string{"/sys/fs/cgroup/memory/symbolon/" + containerID,
		"/sys/fs/cgroup/pids/symbolon/" + containerID,
		"/sys/fs/cgroup/cpu/symbolon/" + containerID}
	if createCGroupDirs {
		if err := createDirs(cgroups); err != nil {
			return red("Failed to create cgroup directories: %v", err)
		}
	}
	for _, cgroupDir := range cgroups {
		if err := os.WriteFile(cgroupDir+"/notify_on_release", []byte("1"), 0700); err != nil {
			return red("Unable to write to cgroup notify_on_release file: %v", err)
		}
		if err := os.WriteFile(cgroupDir+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0700); err != nil {
			return red("Unable to write to cgroup procs file: %v", err)
		}
	}
	return nil
}

func copyNameserverConfig(containerID string) error {
	resolvFilePaths := []string{
		"/var/run/systemd/resolve/resolv.conf",
		"/etc/symbolonresolv.conf",
		"/etc/resolv.conf",
	}
	resolveConf := filepath.Join(SYMBOLON_CONTAINERS_PATH, containerID, "fs", "mnt", "etc", "resolv.conf")
	for _, resolvFilePath := range resolvFilePaths {
		if _, err := os.Stat(resolvFilePath); os.IsNotExist(err) {
			continue
		} else {
			return copyFile(resolvFilePath,
				resolveConf)
		}
	}
	return nil
}

/*
Called if this program is executed with "child-mode" as the first argument
*/
func execContainerCommand(mem int, swap int, pids int, cpus float64, containerID string, imageShaHex string, args []string) error {
	mntPath := filepath.Join(SYMBOLON_CONTAINERS_PATH, containerID, "fs", "mnt")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	imgConfig := parseContainerConfig(imageShaHex)
	if err := unix.Sethostname([]byte(containerID)); err != nil {
		return cli.Exit(red("Unable to set hostname: %v\n", err), 1)

	}
	// joining container network namespace
	/*
		nsMount := filepath.Join(SYMBOLON_NETNS_PATH, containerID)
			if err != nil {
				log.Printf("Unable to open: %v\n", err)
				return cli.Exit(red("Unable to join network: %v\n", err), 1)
			}
		fd, err := unix.Open(nsMount, unix.O_RDONLY, 0)
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			log.Printf("Setns system call failed: %v\n", err)
			return cli.Exit(red("Unable to join network: %v\n", err), 1)
		}
	*/
	var err error
	if err = createCGroups(containerID, true); err != nil {
		return cli.Exit(err, 1)
	}
	//configureCGroups(containerID, mem, swap, pids, cpus)
	//
	if err = copyNameserverConfig(containerID); err != nil {
		return cli.Exit(red("Failed to copy resolv.conf: %v", err), 1)
	}
	if err = unix.Chroot(mntPath); err != nil {
		return cli.Exit(red("Unable to chroot into container: %v\n", err), 1)
	}
	if err = os.Chdir("/"); err != nil {
		return cli.Exit(red("Unable to change directory to /: %v\n", err), 1)
	}
	if err = createDirs([]string{"/proc", "/sys"}); err != nil {
		return cli.Exit(red("Failed to create /proc and /sys directories: %v", err), 1)
	}
	if err = unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return cli.Exit(red("Unable to mount proc filesystem: %v", err), 1)
	}
	if err = unix.Mount("tmpfs", "/tmp", "tmpfs", 0, ""); err != nil {
		return cli.Exit(red("Unable to mount tmpfs on /tmp: %v", err), 1)
	}
	if err = unix.Mount("tmpfs", "/dev", "tmpfs", 0, ""); err != nil {
		return cli.Exit(red("Unable to mount tmpfs on /dev: %v", err), 1)
	}
	if err := createDirs([]string{"/dev/pts"}); err != nil {
		return cli.Exit(red("Failed to create /dev/pts directory: %v", err), 1)
	}
	if err := unix.Mount("devpts", "/dev/pts", "devpts", 0, ""); err != nil {
		return cli.Exit(red("Unable to mount devpts on /dev/pts: %v", err), 1)
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return cli.Exit(red("Unable to mount sysfs on /sys: %v", err), 1)
	}

	// setup local interface by adding a loopback address to the lo interface
	links, _ := netlink.LinkList()
	for _, link := range links {
		if link.Attrs().Name == "lo" {
			loAddr, _ := netlink.ParseAddr("127.0.0.1/32")
			if err := netlink.AddrAdd(link, loAddr); err != nil {
				log.Println("Unable to configure local interface!")
			}
			netlink.LinkSetUp(link)
		}
	}

	cmd.Env = imgConfig.Config.Env
	cmd.Run()
	if err := unix.Unmount("/dev/pts", 0); err != nil {
		return cli.Exit(red("Failed to unmount /dev/pts: %v", err), 1)
	}
	if err := unix.Unmount("/dev", 0); err != nil {
		return cli.Exit(red("Failed to unmount /dev: %v", err), 1)
	}
	if err := unix.Unmount("/sys", 0); err != nil {
		return cli.Exit(red("Failed to unmount /sys: %v", err), 1)
	}
	if err := unix.Unmount("/proc", 0); err != nil {
		return cli.Exit(red("Failed to unmount /proc: %v", err), 1)
	}
	if err := unix.Unmount("/tmp", 0); err != nil {
		return cli.Exit(red("Failed to unmount /tmp: %v", err), 1)
	}
	return nil
}

func printAvailableImages() {
	idb := metadata{}
	parseMetadata(&idb)
	var data [][]string
	//fmt.Printf("IMAGE\t\t\tTAG\t\t\tID\n")
	data = make([][]string, 0, len(idb))
	data = append(data, []string{"IMAGE", "TAG", "ID"})
	for image, details := range idb {
		for tag, hash := range details {
			data = append(data, []string{image, tag, hash})
			//fmt.Printf("%s\t%18s\t\t%s\n", image, tag, hash)
		}
	}

	// Configure colors: green headers, cyan/magenta rows, yellow footer
	colorCfg := renderer.ColorizedConfig{
		Header: renderer.Tint{
			FG: renderer.Colors{color.FgGreen, color.Bold}, // Green bold headers
		},
		Column: renderer.Tint{
			FG: renderer.Colors{color.FgWhite},
		},
	}
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewColorized(colorCfg)),
	)
	table.Header(data[0])
	table.Bulk(data[1:])
	table.Render()
}

func Cli() {
	cmd := &cli.Command{
		Name:                  "symbolon-core",
		Usage:                 "blah blah blah",
		EnableShellCompletion: true,
		Version:               "0.1.0",
		// Authors: []any{
		// 	"amarjay<abdmananjnr@gmail.com>",
		// },
		// Copyright:   "MIT License (MIT)",
		HideVersion: true,
		Suggest:     true,
		Description: "This is a CLI for Symbolon Core, a tool for managing containers and networks.",
		Commands: []*cli.Command{
			{
				Name:        "ps",
				Usage:       "List running containers",
				Description: "This command lists all running containers with their IDs and names.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Listing running containers...[not implemented yet]")
					// Here you would typically fetch the list of running containers
					return nil
				},
			},
			{

				Name:        "images",
				Usage:       "List available container images",
				Description: "This command lists all available container images with their IDs and names.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					println("Listing available container images:")
					printAvailableImages()
					return nil
				},
			},

			{

				Name:        "rmi",
				Usage:       "Remove a container image",
				Description: "This command removes a container image by its ID or name.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Removing a container image...[not implemented yet]")
					// This is where you would typically fetch the list of available images
					return nil
				},
			},
			{
				Name:        "build",
				Usage:       "Build a container image",
				Description: "This command builds a container image from a script",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Running a container...[not implemented yet]")
					return nil
				},
			},
			{
				Name:        "run",
				Usage:       "Run a container",
				Description: "This command runs a container with the specified image and options.",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name:      "image",
						UsageText: "The image to run",
					},
					&cli.StringArg{
						Name:      "options",
						UsageText: "Options for running the container",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Running a container...[not implemented yet]")
					if cmd.StringArg("image") == "" {
						return cli.Exit(red("You must specify an image to run."), 1)
					}
					if err := setupBridge(); err != nil {
						return err
					}
					return setupContainer(cmd.StringArg("image"), cmd.StringArg("options"))
				},
			},

			{
				Name:        "setup",
				Usage:       "Run a setup command",
				Description: "This command runs a setup command for the Symbolon Core.",
				Commands: []*cli.Command{
					{
						Name:        "netns",
						Usage:       "Setup network namespace for a container",
						Description: "This command sets up a network namespace for a container by its ID.",
						Arguments: []cli.Argument{
							&cli.StringArg{
								Name:      "container_id",
								UsageText: "The ID of the container to set up the network namespace for",
							},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return setupNewNetworkNamespace(cmd.StringArg("container_id"))
						},
					},
					{
						Name:  "child-mode",
						Usage: "Run a child process in a new PID namespace",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "container_id",
								Usage: "The ID of the container to set up the network namespace for",
							},
							&cli.StringFlag{
								Name:  "options",
								Usage: "Options for running the container",
							},
							&cli.StringFlag{
								Name:  "image",
								Usage: "The image to run",
							},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							id := cmd.String("container_id")
							if id == "" {
								return cli.Exit(red("You must specify an container id to run."), 1)
							}
							options := strings.Split(cmd.StringArg("options"), " ")
							return execContainerCommand(-1, -1, -1, -1, id, cmd.String("image"), options)
						},
					},
				},
			},

			{
				Name:        "exec",
				Usage:       "Execute a command in a running container",
				Description: "This command executes a command in a running container by its ID or name.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Executing a command in a running container...[not implemented yet]")
					return nil
				},
			},
			{
				Name:        "stop",
				Usage:       "Stop a running container",
				Description: "This command stops a running container by its ID or name.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Stopping a container...[not implemented yet]")
					return nil
				},
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose output",
			},
			&cli.BoolFlag{
				Name:    "detach",
				Aliases: []string{"d"},
				Usage:   "Run the container in detached mode",
				Value:   false,
			},
		},
		Arguments: []cli.Argument{
			&cli.IntArg{
				Name:      "someint",
				UsageText: "some integer",
			},
			&cli.StringArg{
				Name: "_someint",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if os.Geteuid() != 0 {
				return cli.Exit(red("You need root privileges to run this program."), 126)
			}

			// print all arguments
			fmt.Printf("Arguments: %v\n", cmd.Args().Slice())
			// Create necessary directories if they do not exist
			dirs := []string{
				SYMBOLON_TMP_PATH,
				SYMBOLON_IMAGES_PATH,
				SYMBOLON_DB_PATH,
				SYMBOLON_CONTAINERS_PATH,
				SYMBOLON_NETNS_PATH,
			}
			if err := createDirs(dirs); err != nil {
				return err
			}

			fmt.Printf("We all right mate %d", cmd.IntArg("someint"))
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func main() {
	Cli()
}
