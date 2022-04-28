package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	OutputFormat          string `yaml:"output-format"`
	DetectOriginalSyscall bool   `yaml:"detect-original-syscall"`
	PerfBufferSize        int    `yaml:"perf-buffer-size"`
	ShowAllSyscalls       bool   `yaml:"show-all-syscalls"`
	OutputPath            string `yaml:"output-path"`
	//"Capture artifacts that were written, executed or found to be suspicious.
	//captured artifacts will appear in the 'output-path' directory.
	//possible values: 'write'/'exec'/'mem'/'all'.
	//use this flag multiple times to choose multiple Capture options",
	Capture string `yaml:"capture"`
}

func GetConfigFromYml() (*config, error) {
	exePath, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	confFilePath := filepath.Join(filepath.Dir(exePath), "./ctrace/conf.yaml")
	_, err = os.Stat(confFilePath)
	if !os.IsNotExist(err) {
		yamlFile, err := ioutil.ReadFile(confFilePath)
		c := &config{}
		err = yaml.Unmarshal(yamlFile, c)
		if err != nil {
			return nil, fmt.Errorf("can not load config: %v", err)
		}
		if c.OutputFormat != "table" && c.OutputFormat != "json" && c.OutputFormat != "gob" {
			return nil, fmt.Errorf("unrecognized output format: %s", c.OutputFormat)
		}
		if (c.PerfBufferSize & (c.PerfBufferSize - 1)) != 0 {
			return nil, fmt.Errorf("invalid perf buffer size - must be a power of 2")
		}
		return c, nil
	}
	return nil, fmt.Errorf("conf.yaml not found: %v", err)
}

func UpdateConfig(key string, newvalue []byte, conf *config) error {
	setDefault := newvalue == nil || len(newvalue) == 0
	if key == "output-format" {
		if setDefault {
			conf.OutputFormat = ""
			return nil
		}
		output_format := string(newvalue)
		if output_format != "table" && output_format != "json" && output_format != "gob" {
			return fmt.Errorf("unrecognized output format: %s", output_format)
		}
		conf.OutputFormat = output_format
	} else if key == "detect-original-syscall" {
		if setDefault {
			conf.DetectOriginalSyscall = false
		} else {
			detect_original_syscall, err := strconv.ParseBool(string(newvalue))
			if err != nil {
				return fmt.Errorf("invalid detect  original syscall value: %v", err)
			}
			conf.DetectOriginalSyscall = detect_original_syscall
		}
	} else if key == "perf-buffer-size" {
		if setDefault {
			conf.PerfBufferSize = 64
		} else {
			perf_buffer_size, err := strconv.ParseInt(string(newvalue), 10, 32)
			if err != nil {
				return fmt.Errorf("invalid perf buffer size value: %v", err)
			}
			if (perf_buffer_size & (perf_buffer_size - 1)) != 0 {
				return fmt.Errorf("invalid perf buffer size - must be a power of 2")
			}
			conf.PerfBufferSize = int(perf_buffer_size)
		}
	} else if key == "show-all-syscalls" {
		if setDefault {
			conf.DetectOriginalSyscall = false
		} else {
			show_all_syscalls, err := strconv.ParseBool(string(newvalue))
			if err != nil {
				return fmt.Errorf("invalid show all syscalls value: %v", err)
			}
			conf.DetectOriginalSyscall = show_all_syscalls
		}
	} else if key == "output-path" {
		if setDefault {
			conf.OutputPath = ""
			return nil
		} else {
			output_path := string(newvalue)
			//to-do validate the output_path
			conf.OutputPath = output_path
		}
	} else if key == "capture" {
		if setDefault {
			conf.Capture = ""
			return nil
		} else {
			capture := strings.Split(string(newvalue), "|")
			for _, cap := range capture {
				if cap != "men" && cap != "write" && cap != "exec" && cap != "all" {
					return fmt.Errorf("invalid capture value :%s", cap)
				}
			}
			conf.Capture = string(newvalue)
		}
	} else {
		return fmt.Errorf("not such config key")
	}

	if err := WriteBackConf(conf); err != nil {
		return fmt.Errorf("conf.yaml write fail: %v\n", err)
	}
	return nil
}

func WriteBackConf(newConf *config) error {
	out, err := yaml.Marshal(newConf)
	if err != nil {
		return fmt.Errorf("can not translate to conf.yaml: %v", err)
	}
	exePath, err := os.Getwd()
	if err != nil {
		return err
	}
	confFilePath := filepath.Join(filepath.Dir(exePath), "./ctrace/conf.yaml")
	_, err = os.Stat(confFilePath)
	if !os.IsNotExist(err) {
		err = ioutil.WriteFile(confFilePath, out, 0777)
		if err != nil {
			return fmt.Errorf("can not write conf.yaml: %v", err)
		}
		return nil
	}
	return fmt.Errorf("conf.yaml not found: %v", err)
}

func PrintConfig(conf *config) error {
	out, err := yaml.Marshal(conf)
	if err != nil {
		return fmt.Errorf("can not translate to conf.yaml: %v", err)
	}
	fmt.Println(string(out))
	return nil
}
