pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo "Building the TFTP client"'
                sh 'cc -std=c99 tftp.c -o tftp'
            }
        }
    }
    stages {
    	   success {
	      echo 'Pipeline ran OK'
	   }
	   failure {
	      echo 'The Pipeline FAILED'
	   }
	   changed {
	      echo 'This pipeline has changed state'
           }
    }
}