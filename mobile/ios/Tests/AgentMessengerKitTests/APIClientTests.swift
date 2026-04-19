import XCTest
@testable import AgentMessengerKit

final class APIClientTests: XCTestCase {

    func testAPIErrorDescriptions() {
        let invalidURL = APIError.invalidURL
        XCTAssertEqual(invalidURL.errorDescription, "Invalid server URL")

        let unauthorized = APIError.unauthorized
        XCTAssertEqual(unauthorized.errorDescription, "Invalid credentials")

        let serverError = APIError.serverError("Something went wrong")
        XCTAssertEqual(serverError.errorDescription, "Something went wrong")

        let decodingError = APIError.decodingError
        XCTAssertEqual(decodingError.errorDescription, "Failed to parse server response")
    }

    func testAPIErrorNetworkError() {
        let error = NSError(domain: NSURLErrorDomain, code: NSURLErrorNotConnectedToInternet, userInfo: nil)
        let apiError = APIError.networkError(error)
        XCTAssertNotNil(apiError.errorDescription)
        XCTAssertFalse(apiError.errorDescription!.isEmpty)
    }

    func testConfigWithCustomServer() {
        let config = AppConfig(serverURL: "ws://192.168.1.100:9090", apiURL: "http://192.168.1.100:9090")
        let client = APIClient(config: config)
        XCTAssertNotNil(client)
    }
}