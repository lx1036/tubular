package pidfd

import (
	"fmt"
	"testing"

	"github.com/cloudflare/tubular/internal/testutil"
)

func TestFiles(t *testing.T) {
	const numFiles = 10

	child := testutil.SpawnChildWithFiles(t, testutil.OpenFiles(t, numFiles-3)...)

	var count int
	files, err := Files(child, func(fd int) (bool, error) {
		count++
		return count%2 == 0, nil
	})
	if err != nil {
		t.Fatal("Can't get files of child process:", err)
	}

	if count != numFiles {
		t.Errorf("Expected to find %d open files, got %d", numFiles, count)
	}

	if want := numFiles / 2; len(files) != want {
		t.Errorf("Expected %d files, got %d", want, len(files))
	}
}

// go test -v -run ^TestPidFiles$ .
func TestPidFiles(t *testing.T) {
	pid := 205241
	files, err := Files(int(pid))
	if err != nil {
		t.Fatal(fmt.Sprintf("pid %d: %v", pid, err))
	}

	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	for _, file := range files {
		fmt.Println(fmt.Sprintf("fd:%d name:%s", int(file.Fd()), file.Name()))
	}

	fmt.Println(fmt.Sprintf("success %d", pid))
}
