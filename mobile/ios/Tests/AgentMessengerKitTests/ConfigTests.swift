import XCTest
@testable import AgentMessengerKit

final class ConfigTests: XCTestCase {

    override func setUp() {
        // Clear saved config before each test
        UserDefaults.standard.removeObject(forKey: "app_config")
    }

    func testDefaultConfig() {
        let config = AppConfig()
        XCTAssertEqual(config.serverURL, "ws://localhost:8080")
        XCTAssertEqual(config.apiURL, "http://localhost:8080")
        XCTAssertEqual(config.username, "")
        XCTAssertEqual(config.password, "")
        XCTAssertFalse(config.isConfigured)
    }

    func testCustomConfig() {
        let config = AppConfig(
            serverURL: "ws://example.com:9090",
            apiURL: "http://example.com:9090",
            username: "testuser",
            password: "secret"
        )
        XCTAssertEqual(config.serverURL, "ws://example.com:9090")
        XCTAssertEqual(config.apiURL, "http://example.com:9090")
        XCTAssertEqual(config.username, "testuser")
        XCTAssertTrue(config.isConfigured)
    }

    func testConfigSaveAndLoad() {
        let config = AppConfig(
            serverURL: "ws://test.local:8080",
            apiURL: "http://test.local:8080",
            username: "myuser",
            password: "pass123"
        )
        config.save()

        let loaded = AppConfig.load()
        XCTAssertEqual(loaded.serverURL, config.serverURL)
        XCTAssertEqual(loaded.apiURL, config.apiURL)
        XCTAssertEqual(loaded.username, config.username)
        XCTAssertEqual(loaded.password, config.password)
    }

    func testConfigLoadMissing() {
        let config = AppConfig.load()
        // Should return defaults when no config saved
        XCTAssertEqual(config.serverURL, "ws://localhost:8080")
        XCTAssertEqual(config.username, "")
    }

    func testConfigDelete() {
        let config = AppConfig(username: "deleteme", password: "xxx")
        config.save()
        AppConfig.delete()
        let loaded = AppConfig.load()
        XCTAssertEqual(loaded.username, "")
    }

    func testIsConfigured() {
        let emptyConfig = AppConfig()
        XCTAssertFalse(emptyConfig.isConfigured)

        let configured = AppConfig(username: "myuser", password: "pass")
        XCTAssertTrue(configured.isConfigured)

        // Missing password
        let noPassword = AppConfig(username: "myuser", password: "")
        XCTAssertFalse(noPassword.isConfigured)
    }
}