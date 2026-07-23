pipeline {
    agent any

    environment {
        GUARDRAIL_IMAGE = 'ai-cicd-security-guardrail'
        REPORT_PATH = 'tests/fixtures/sample.sarif'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Guardrail Image') {
            steps {
                script {
                    sh "docker build -t ${env.GUARDRAIL_IMAGE} ."
                }
            }
        }

        stage('Run Static Analysis') {
            steps {
                script {
                    // This is a placeholder. In a real pipeline you would run
                    // SonarQube, cppcheck, or another SAST tool and export
                    // the report to the workspace.
                    echo "Run your static analysis tool here (SonarQube, cppcheck, etc.)"
                }
            }
        }

        stage('Triage with AI Guardrail') {
            steps {
                script {
                    sh """
                        docker run --rm \
                            -v \$(pwd):/workspace \
                            -e GUARDRAIL_LLM_PROVIDER=mock \
                            ${env.GUARDRAIL_IMAGE} \
                            ${env.REPORT_PATH} \
                            --repo-root /workspace \
                            --output-json guardrail-report.json \
                            --output-markdown guardrail-report.md
                    """
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'guardrail-report.*', allowEmptyArchive: true
        }
        failure {
            echo 'Guardrail detected high-priority or unclear findings. Review the report.'
        }
    }
}
