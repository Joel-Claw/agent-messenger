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
        XCTAssertEqual(config.email, "")
        XCTAssertEqual(config.password, "")
        XCTAssertFalse(config.isConfigured)
    }

    func testCustomConfig() {
        let config = AppConfig(
            serverURL: "ws://example.com:9090",
            apiURL: "http://example.com:9090",
            email: "test@example.com",
            password: "secret"
        )
        XCTAssertEqual(config.serverURL, "ws://example.com:9090")
        XCTAssertEqual(config.apiURL, "http://example.com:9090")
        XCTAssertEqual(config.email, "test@example.com")
        XCTAssertTrue(config.isConfigured)
    }

    func testConfigSaveAndLoad() {
        let config = AppConfig(
            serverURL: "ws://test.local:8080",
            apiURL: "http://test.local:8080",
            email: "user@test.com",
            password: "pass123"
        )
        config.save()

        let loaded = AppConfig.load()
        XCTAssertEqual(loaded.serverURL, config.serverURL)
        XCTAssertEqual(loaded.apiURL, config.apiURL)
        XCTAssertEqual(loaded.email, config.email)
        XCTAssertEqual(loaded.password, config.password)
    }

    func testConfigLoadMissing() {
        let config = AppConfig.load()
        // Should return defaults when no config saved
        XCTAssertEqual(config.serverURL, "ws://localhost:8080")
        XCTAssertEqual(config.email, "")
    }

    func testConfigDelete() {
        let config = AppConfig(email: "deleteme@test.com", password: "xxx")
        config.save()
        AppConfig.delete()
        let loaded = AppConfig.load()
        XCTAssertEqual(loaded.email, "")
    }

    func testIsConfigured() {
        let emptyConfig = AppConfig()
        XCTAssertFalse(emptyConfig.isConfigured)

        let configured = AppConfig(email: "user@example.com", password: "pass")
        XCTAssertTrue(configured.isConfigured)

        // Missing password
        let noPassword = AppConfig(email: "user@example.com", password: "")
        XCTAssertFalse(noPassword.isConfigured)
    }
}