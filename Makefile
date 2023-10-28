go_mobile:
	go install golang.org/x/mobile/cmd/gomobile@latest
	gomobile init

android_client:
	gomobile bind -v -target=android -o ./android/passlysdk.aar ./pkg/passly
