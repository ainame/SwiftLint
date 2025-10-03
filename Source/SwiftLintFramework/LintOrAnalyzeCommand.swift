#if os(macOS)
@preconcurrency import Darwin
#endif
import Dispatch
import Foundation

// swiftlint:disable file_length

package enum LintOrAnalyzeMode {
    case lint, analyze

    package var imperative: String {
        switch self {
        case .lint:
            return "lint"
        case .analyze:
            return "analyze"
        }
    }

    package var verb: String {
        switch self {
        case .lint:
            return "linting"
        case .analyze:
            return "analyzing"
        }
    }
}

package struct LintOrAnalyzeOptions {
    let mode: LintOrAnalyzeMode
    let paths: [String]
    let useSTDIN: Bool
    let configurationFiles: [String]
    let strict: Bool
    let lenient: Bool
    let forceExclude: Bool
    let useExcludingByPrefix: Bool
    let useScriptInputFiles: Bool
    let useScriptInputFileLists: Bool
    let benchmark: Bool
    let reporter: String?
    let baseline: String?
    let writeBaseline: String?
    let workingDirectory: String?
    let quiet: Bool
    let output: String?
    let progress: Bool
    let cachePath: String?
    let ignoreCache: Bool
    let enableAllRules: Bool
    let onlyRule: [String]
    let autocorrect: Bool
    let format: Bool
    let compilerLogPath: String?
    let compileCommands: String?
    let checkForUpdates: Bool

    package init(mode: LintOrAnalyzeMode,
                 paths: [String],
                 useSTDIN: Bool,
                 configurationFiles: [String],
                 strict: Bool,
                 lenient: Bool,
                 forceExclude: Bool,
                 useExcludingByPrefix: Bool,
                 useScriptInputFiles: Bool,
                 useScriptInputFileLists: Bool,
                 benchmark: Bool,
                 reporter: String?,
                 baseline: String?,
                 writeBaseline: String?,
                 workingDirectory: String?,
                 quiet: Bool,
                 output: String?,
                 progress: Bool,
                 cachePath: String?,
                 ignoreCache: Bool,
                 enableAllRules: Bool,
                 onlyRule: [String],
                 autocorrect: Bool,
                 format: Bool,
                 compilerLogPath: String?,
                 compileCommands: String?,
                 checkForUpdates: Bool) {
        self.mode = mode
        self.paths = paths
        self.useSTDIN = useSTDIN
        self.configurationFiles = configurationFiles
        self.strict = strict
        self.lenient = lenient
        self.forceExclude = forceExclude
        self.useExcludingByPrefix = useExcludingByPrefix
        self.useScriptInputFiles = useScriptInputFiles
        self.useScriptInputFileLists = useScriptInputFileLists
        self.benchmark = benchmark
        self.reporter = reporter
        self.baseline = baseline
        self.writeBaseline = writeBaseline
        self.workingDirectory = workingDirectory
        self.quiet = quiet
        self.output = output
        self.progress = progress
        self.cachePath = cachePath
        self.ignoreCache = ignoreCache
        self.enableAllRules = enableAllRules
        self.onlyRule = onlyRule
        self.autocorrect = autocorrect
        self.format = format
        self.compilerLogPath = compilerLogPath
        self.compileCommands = compileCommands
        self.checkForUpdates = checkForUpdates
    }

    var verb: String {
        autocorrect ? "correcting" : mode.verb
    }

    var capitalizedVerb: String {
        verb.capitalized
    }
}

package struct LintOrAnalyzeCommand {
    package static func run(_ options: LintOrAnalyzeOptions) async throws {
        let runStartMessage = "LintOrAnalyzeCommand.run start. mode: \(options.mode), pathsCount: \(options.paths.count), " +
            "autocorrect: \(options.autocorrect), progress: \(options.progress)"
        queuedDebugLog(runStartMessage)
        if let workingDirectory = options.workingDirectory {
            let workingDirectoryMessage = "Requested working directory change to: \(workingDirectory)"
            queuedDebugLog(workingDirectoryMessage)
            if !FileManager.default.changeCurrentDirectoryPath(workingDirectory) {
                throw SwiftLintError.usageError(
                    description: """
                                 Could not change working directory to '\(workingDirectory)'. \
                                 Make sure it exists and is accessible.
                                 """
                )
            }
            let currentDirectory = FileManager.default.currentDirectoryPath
            let currentDirectoryMessage = "Working directory set to: \(currentDirectory)"
            queuedDebugLog(currentDirectoryMessage)
        }
        let taskDescription = options.autocorrect ? "autocorrect" : options.mode.verb
        let executingMessage = "LintOrAnalyzeCommand.run executing task: \(taskDescription)"
        queuedDebugLog(executingMessage)
        try await Signposts.record(name: "LintOrAnalyzeCommand.run") {
            try await options.autocorrect ? autocorrect(options) : lintOrAnalyze(options)
        }
        let finishedMessage = "LintOrAnalyzeCommand.run finished task: \(taskDescription)"
        queuedDebugLog(finishedMessage)
    }

    private static func lintOrAnalyze(_ options: LintOrAnalyzeOptions) async throws {
        let lintStartMessage = "LintOrAnalyzeCommand.lintOrAnalyze start. benchmark: \(options.benchmark), quiet: \(options.quiet), " +
            "checkForUpdates: \(options.checkForUpdates)"
        queuedDebugLog(lintStartMessage)
        let builder = LintOrAnalyzeResultBuilder(options)
        let builderMessage = "LintOrAnalyzeCommand.lintOrAnalyze builder ready. reporter: \(builder.reporter), " +
            "cacheEnabled: \(builder.cache != nil)"
        queuedDebugLog(builderMessage)
        let files = try await collectViolations(builder: builder)
        let collectedMessage = "LintOrAnalyzeCommand.lintOrAnalyze collected violations for \(files.count) files. " +
            "Unfiltered violations count: \(builder.unfilteredViolations.count)"
        queuedDebugLog(collectedMessage)
        if let baselineOutputPath = options.writeBaseline ?? builder.configuration.writeBaseline {
            let baselineMessage = "LintOrAnalyzeCommand.lintOrAnalyze writing baseline to: \(baselineOutputPath)"
            queuedDebugLog(baselineMessage)
            try Baseline(violations: builder.unfilteredViolations).write(toPath: baselineOutputPath)
        }
        let numberOfSeriousViolations = try Signposts.record(name: "LintOrAnalyzeCommand.PostProcessViolations") {
            try postProcessViolations(files: files, builder: builder)
        }
        let postProcessMessage = "LintOrAnalyzeCommand.lintOrAnalyze post processing done. Serious violations: \(numberOfSeriousViolations)"
        queuedDebugLog(postProcessMessage)
        if options.checkForUpdates || builder.configuration.checkForUpdates {
            queuedDebugLog("LintOrAnalyzeCommand.lintOrAnalyze checking for updates")
            await UpdateChecker.checkForUpdates()
        }
        if numberOfSeriousViolations > 0 {
            queuedDebugLog("LintOrAnalyzeCommand.lintOrAnalyze exiting with code 2 due to serious violations")
            exit(2)
        }
        queuedDebugLog("LintOrAnalyzeCommand.lintOrAnalyze completed without exiting")
    }

    private static func collectViolations(builder: LintOrAnalyzeResultBuilder) async throws -> [SwiftLintFile] {
        let options = builder.options
        let collectStartMessage = "collectViolations start. useSTDIN: \(options.useSTDIN), pathsCount: \(options.paths.count), " +
            "onlyRuleCount: \(options.onlyRule.count)"
        queuedDebugLog(collectStartMessage)
        let visitorMutationQueue = DispatchQueue(label: "io.realm.swiftlint.lintVisitorMutation")
        let baseline = try baseline(options, builder.configuration)
        let baselineMessage = "collectViolations baseline available: \(baseline != nil)"
        queuedDebugLog(baselineMessage)
        queuedDebugLog("collectViolations preparing to visit lintable files")
        let processedFiles = try await builder.configuration.visitLintableFiles(options: options, cache: builder.cache,
                                                                               storage: builder.storage) { linter in
            let filePath = linter.file.path ?? "<no-path>"
            let visitingFileMessage = "collectViolations visiting file: \(filePath)"
            queuedDebugLog(visitingFileMessage)
            let currentViolations: [StyleViolation]
            if options.benchmark {
                CustomRuleTimer.shared.activate()
                let start = Date()
                let (violationsBeforeLeniency, currentRuleTimes) = linter
                    .styleViolationsAndRuleTimes(using: builder.storage)
                let rawCount = violationsBeforeLeniency.count
                let rawViolationsMessage = "collectViolations benchmark raw violations: \(rawCount) for file: \(filePath)"
                queuedDebugLog(rawViolationsMessage)
                currentViolations = applyLeniency(
                    options: options,
                    strict: builder.configuration.strict,
                    lenient: builder.configuration.lenient,
                    violations: violationsBeforeLeniency
                )
                let leniencyCount = currentViolations.count
                let benchmarkLeniencyMessage = "collectViolations benchmark leniency applied: \(leniencyCount) for file: \(filePath)"
                queuedDebugLog(benchmarkLeniencyMessage)
                visitorMutationQueue.sync {
                    builder.fileBenchmark.record(file: linter.file, from: start)
                    currentRuleTimes.forEach { builder.ruleBenchmark.record(id: $0, time: $1) }
                }
            } else {
                currentViolations = applyLeniency(
                    options: options,
                    strict: builder.configuration.strict,
                    lenient: builder.configuration.lenient,
                    violations: linter.styleViolations(using: builder.storage)
                )
                let leniencyCount = currentViolations.count
                let leniencyMessage = "collectViolations leniency applied: \(leniencyCount) for file: \(filePath)"
                queuedDebugLog(leniencyMessage)
            }
            let filteredViolations = baseline?.filter(currentViolations) ?? currentViolations
            let filteredCount = filteredViolations.count
            let filteredMessage = "collectViolations filtered violations: \(filteredCount) for file: \(filePath)"
            queuedDebugLog(filteredMessage)
            visitorMutationQueue.sync {
                builder.unfilteredViolations += currentViolations
                builder.violations += filteredViolations
            }

            linter.file.invalidateCache()
            let invalidatedMessage = "collectViolations invalidated cache for file: \(filePath)"
            queuedDebugLog(invalidatedMessage)
            builder.report(violations: filteredViolations, realtimeCondition: true)
            let reportedMessage = "collectViolations reported violations for file: \(filePath)"
            queuedDebugLog(reportedMessage)
        }
        let processedMessage = "collectViolations completed. processedFilesCount: \(processedFiles.count)"
        queuedDebugLog(processedMessage)
        return processedFiles
    }

    private static func postProcessViolations(
        files: [SwiftLintFile],
        builder: LintOrAnalyzeResultBuilder
    ) throws -> Int {
        let options = builder.options
        let configuration = builder.configuration
        let postStartMessage = "postProcessViolations start. filesCount: \(files.count), currentViolations: \(builder.violations.count)"
        queuedDebugLog(postStartMessage)
        if isWarningThresholdBroken(configuration: configuration, violations: builder.violations), !options.lenient {
            builder.violations.append(
                createThresholdViolation(threshold: configuration.warningThreshold!)
            )
            builder.report(violations: [builder.violations.last!], realtimeCondition: true)
            queuedDebugLog("postProcessViolations warning threshold exceeded. Added threshold violation")
        }
        builder.report(violations: builder.violations, realtimeCondition: false)
        let aggregateMessage = "postProcessViolations reported aggregate violations: \(builder.violations.count)"
        queuedDebugLog(aggregateMessage)
        let numberOfSeriousViolations = builder.violations.filter({ $0.severity == .error }).count
        if !options.quiet {
            printStatus(violations: builder.violations, files: files, serious: numberOfSeriousViolations,
                        verb: options.verb)
        }
        if options.benchmark {
            builder.fileBenchmark.save()
            for (id, time) in CustomRuleTimer.shared.dump() {
                builder.ruleBenchmark.record(id: id, time: time)
            }
            builder.ruleBenchmark.save()
            if !options.quiet, let memoryUsage = memoryUsage() {
                queuedPrintError(memoryUsage)
            }
            queuedDebugLog("postProcessViolations saved benchmark data")
        }
        try builder.cache?.save()
        let cacheMessage = "postProcessViolations cache save attempted. cacheEnabled: \(builder.cache != nil)"
        queuedDebugLog(cacheMessage)
        let seriousMessage = "postProcessViolations serious violations count: \(numberOfSeriousViolations)"
        queuedDebugLog(seriousMessage)
        return numberOfSeriousViolations
    }

    private static func baseline(_ options: LintOrAnalyzeOptions, _ configuration: Configuration) throws -> Baseline? {
        if let baselinePath = options.baseline ?? configuration.baseline {
            let baselineLoadMessage = "baseline loading from path: \(baselinePath)"
            queuedDebugLog(baselineLoadMessage)
            do {
                let loaded = try Baseline(fromPath: baselinePath)
                let baselineSuccessMessage = "baseline successfully loaded from path: \(baselinePath)"
                queuedDebugLog(baselineSuccessMessage)
                return loaded
            } catch {
                let baselineFailureMessage = "baseline failed to load from path: \(baselinePath) with error: \(error)"
                queuedDebugLog(baselineFailureMessage)
                Issue.baselineNotReadable(path: baselinePath).print()
                if (error as? CocoaError)?.code != CocoaError.fileReadNoSuchFile ||
                        options.writeBaseline != options.baseline {
                    throw error
                }
            }
        }
        return nil
    }

    private static func printStatus(violations: [StyleViolation], files: [SwiftLintFile], serious: Int, verb: String) {
        let pluralSuffix = { (collection: [Any]) -> String in
            collection.count != 1 ? "s" : ""
        }
        queuedPrintError(
            "Done \(verb)! Found \(violations.count) violation\(pluralSuffix(violations)), " +
            "\(serious) serious in \(files.count) file\(pluralSuffix(files))."
        )
    }

    private static func isWarningThresholdBroken(configuration: Configuration,
                                                 violations: [StyleViolation]) -> Bool {
        guard let warningThreshold = configuration.warningThreshold else { return false }
        let numberOfWarningViolations = violations.filter({ $0.severity == .warning }).count
        return numberOfWarningViolations >= warningThreshold
    }

    private static func createThresholdViolation(threshold: Int) -> StyleViolation {
        let description = RuleDescription(
            identifier: "warning_threshold",
            name: "Warning Threshold",
            description: "Number of warnings thrown is above the threshold",
            kind: .lint
        )
        return StyleViolation(
            ruleDescription: description,
            severity: .error,
            location: Location(file: "", line: 0, character: 0),
            reason: "Number of warnings exceeded threshold of \(threshold).")
    }

    private static func applyLeniency(
        options: LintOrAnalyzeOptions,
        strict: Bool,
        lenient: Bool,
        violations: [StyleViolation]
    ) -> [StyleViolation] {
        let leniency = options.leniency(strict: strict, lenient: lenient)

        switch leniency {
        case (false, false):
            return violations

        case (false, true):
            return violations.map {
                if $0.severity == .error {
                    return $0.with(severity: .warning)
                }
                return $0
            }

        case (true, false):
            return violations.map {
                if $0.severity == .warning {
                    return $0.with(severity: .error)
                }
                return $0
            }

        case (true, true):
            queuedFatalError("Invalid command line or config options: 'strict' and 'lenient' are mutually exclusive.")
        }
    }

    private static func autocorrect(_ options: LintOrAnalyzeOptions) async throws {
        let storage = RuleStorage()
        let configuration = Configuration(options: options)
        let correctionsBuilder = CorrectionsBuilder()
        let files = try await configuration
            .visitLintableFiles(options: options, cache: nil, storage: storage) { linter in
                if options.format {
                    switch configuration.indentation {
                    case .tabs:
                        linter.format(useTabs: true, indentWidth: 4)
                    case .spaces(let count):
                        linter.format(useTabs: false, indentWidth: count)
                    }
                }

                let corrections = linter.correct(using: storage)
                if !corrections.isEmpty, !options.quiet {
                    if options.useSTDIN {
                        queuedPrint(linter.file.contents)
                    } else {
                        let corrections = corrections.map {
                            Correction(
                                ruleName: $0.0,
                                filePath: linter.file.path,
                                numberOfCorrections: $0.1
                            )
                        }
                        if options.progress {
                            await correctionsBuilder.append(corrections)
                        } else {
                            let correctionLogs = corrections.map(\.consoleDescription)
                            queuedPrint(correctionLogs.joined(separator: "\n"))
                        }
                    }
                }
            }

        if !options.quiet {
            if options.progress {
                let corrections = await correctionsBuilder.corrections
                if !corrections.isEmpty {
                    let correctionLogs = corrections.map(\.consoleDescription)
                    options.writeToOutput(correctionLogs.joined(separator: "\n"))
                }
            }

            let pluralSuffix = { (collection: [Any]) -> String in
                collection.count != 1 ? "s" : ""
            }
            queuedPrintError("Done correcting \(files.count) file\(pluralSuffix(files))!")
        }
    }
}

private class LintOrAnalyzeResultBuilder {
    var fileBenchmark = Benchmark(name: "files")
    var ruleBenchmark = Benchmark(name: "rules")
    /// All detected violations, unfiltered by the baseline, if any.
    var unfilteredViolations = [StyleViolation]()
    /// The violations to be reported, possibly filtered by a baseline, plus any threshold violations.
    var violations = [StyleViolation]()
    let storage = RuleStorage()
    let configuration: Configuration
    let reporter: any Reporter.Type
    let cache: LinterCache?
    let options: LintOrAnalyzeOptions

    init(_ options: LintOrAnalyzeOptions) {
        let initStartMessage = "LintOrAnalyzeResultBuilder init start. configurationFiles: \(options.configurationFiles), " +
            "cachePath: \(String(describing: options.cachePath)), enableAllRules: \(options.enableAllRules)"
        queuedDebugLog(initStartMessage)
        let config = Signposts.record(name: "LintOrAnalyzeCommand.ParseConfiguration") {
            Configuration(options: options)
        }
        configuration = config
        let configMessage = "LintOrAnalyzeResultBuilder configuration resolved. rulesCount: \(config.rules.count), " +
            "rootDirectory: \(config.rootDirectory)"
        queuedDebugLog(configMessage)
        let resolvedReporter = reporterFrom(identifier: options.reporter ?? config.reporter)
        reporter = resolvedReporter
        let reporterMessage = "LintOrAnalyzeResultBuilder reporter resolved: \(resolvedReporter)"
        queuedDebugLog(reporterMessage)
        let cacheInstance: LinterCache?
        if options.ignoreCache || ProcessInfo.processInfo.isLikelyXcodeCloudEnvironment {
            cacheInstance = nil
        } else {
            cacheInstance = LinterCache(configuration: config)
        }
        cache = cacheInstance
        let cacheEnabled = cacheInstance != nil
        let cacheMessage = "LintOrAnalyzeResultBuilder cache enabled: \(cacheEnabled)"
        queuedDebugLog(cacheMessage)
        self.options = options

        if let outFile = options.output {
            do {
                try Data().write(to: URL(fileURLWithPath: outFile))
            } catch {
                Issue.fileNotWritable(path: outFile).print()
            }
        }
        queuedDebugLog("LintOrAnalyzeResultBuilder init complete")
    }

    func report(violations: [StyleViolation], realtimeCondition: Bool) {
        if (reporter.isRealtime && (!options.progress || options.output != nil)) == realtimeCondition {
            let report = reporter.generateReport(violations)
            if !report.isEmpty {
                options.writeToOutput(report)
            }
        }
    }
}

extension LintOrAnalyzeOptions {
    fileprivate func writeToOutput(_ string: String) {
        guard let outFile = output else {
            queuedPrint(string)
            return
        }

        do {
            let outFileURL = URL(fileURLWithPath: outFile)
            let fileUpdater = try FileHandle(forUpdating: outFileURL)
            fileUpdater.seekToEndOfFile()
            fileUpdater.write(Data((string + "\n").utf8))
            fileUpdater.closeFile()
        } catch {
            Issue.fileNotWritable(path: outFile).print()
        }
    }

    typealias Leniency = (strict: Bool, lenient: Bool)

    // Config file settings can be overridden by either `--strict` or `--lenient` command line options.
    func leniency(strict configurationStrict: Bool, lenient configurationLenient: Bool) -> Leniency {
        let strict = self.strict || (configurationStrict && !self.lenient)
        let lenient = self.lenient || (configurationLenient && !self.strict)
        return Leniency(strict: strict, lenient: lenient)
    }
}

private actor CorrectionsBuilder {
    private(set) var corrections: [Correction] = []

    func append(_ corrections: [Correction]) {
        self.corrections.append(contentsOf: corrections)
    }
}

private func memoryUsage() -> String? {
#if os(Linux)
    return nil
#else
    var info = mach_task_basic_info()
    let basicInfoCount = MemoryLayout<mach_task_basic_info>.stride / MemoryLayout<natural_t>.stride
    var count = mach_msg_type_number_t(basicInfoCount)

    let kerr: kern_return_t = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: basicInfoCount) {
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
        }
    }

    if kerr == KERN_SUCCESS {
        let bytes = Measurement<UnitInformationStorage>(value: Double(info.resident_size), unit: .bytes)
        let formatted = ByteCountFormatter().string(from: bytes)
        return "Memory used: \(formatted)"
    }
    let errorMessage = String(cString: mach_error_string(kerr), encoding: .ascii)
    return "Error with task_info(): \(errorMessage ?? "unknown")"
#endif
}
