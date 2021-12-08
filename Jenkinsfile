pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo "Building the TFTP client"'
                sh '''
                sh 'cc -std=c99 tftp.c -o tftp'
                '''
            }
        }
    }
}