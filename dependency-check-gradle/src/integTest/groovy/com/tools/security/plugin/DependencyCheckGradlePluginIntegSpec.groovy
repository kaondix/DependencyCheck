package com.tools.security.plugin

import nebula.test.IntegrationSpec
import nebula.test.functional.ExecutionResult

/**
 * @author Sion Williams
 */
class DependencyCheckGradlePluginIntegSpec extends IntegrationSpec {
    def "I can add the plugin to a build with no errors"() {
        setup:
        buildFile << '''
            apply plugin: 'dependency-check'
        '''.stripIndent()

        when:
        ExecutionResult result = runTasksSuccessfully('tasks')

        then:
        result.standardOutput.contains('dependencyCheck - Produce dependency security report.')
    }

    def "I can override outputDir with extension"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('outputDir.gradle', 'build.gradle')

        when:
        runTasksSuccessfully('dependencyCheck')

        then:
        fileExists('build/dependencyCheckReport')
    }

    def "plugin defaults to analysing all configs"() {
        setup:
        buildFile << '''
            configurations {
              myConfig
              myConfigTwo
            }

            repositories {
              mavenCentral()
            }

            dependencies {
              myConfig group: 'commons-collections', name: 'commons-collections', version: '3.2\'
              myConfigTwo group: 'junit', name: 'junit', version: '4.+\'
            }

            apply plugin: 'dependency-check\'
            '''.stripIndent()

        when:
        ExecutionResult result = runTasksSuccessfully('dependencyCheck')

        then:
        result.standardOutput.contains('Artifact name: commons-collections-3.2.jar')
        result.standardOutput.contains('Artifact name: junit-4.12.jar')
    }

    def "Only user defined configuration is analysed"() {
        setup:
        buildFile << '''
            configurations {
              myConfig
              myConfigTwo
            }

            repositories {
              mavenCentral()
            }

            dependencies {
              myConfig group: 'commons-collections', name: 'commons-collections', version: '3.2\'
              myConfigTwo group: 'junit', name: 'junit', version: '4.+\'
            }

            apply plugin: 'dependency-check\'

            dependencyCheck {
              configurationName = "myConfig"
            }'''.stripIndent()

        when:
        ExecutionResult result = runTasksSuccessfully('dependencyCheck')

        then: "log should not contain other configuration artifact"
        !result.standardOutput.contains('Artifact name: junit-4.12.jar')
    }
}
