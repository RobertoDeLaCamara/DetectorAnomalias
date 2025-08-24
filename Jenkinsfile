pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                // Checkout the source code from the Git repository
                git branch: 'master', url: 'https://github.com/RobertoDeLaCamara/DetectorAnomalias.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                // Build the Docker image
                script {
                    sh 'docker build -t anomaly-detector-app .'
                }
            }
        }

        stage('Run Tests') {
            steps {
                // Run tests inside the Docker container
                script {
                    sh 'docker run --rm anomaly-detector-app python -m pytest'
                }
            }
        }
    }

    post {
        always {
            // Clean up Docker images
            script {
                sh 'docker rmi anomaly-detector-app || true'
            }
        }
    }
}
