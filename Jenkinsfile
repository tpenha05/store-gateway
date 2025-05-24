pipeline {
    agent any
    
    tools {
        maven 'maven-3'
        jdk 'jdk-21'
    }
    
    environment {
        SERVICE = 'gateway'
        NAME = "tpenha05/${env.SERVICE}"
        REGISTRY_CREDENTIALS = 'dockerhub-credentials'
    }
    
    stages {
        stage('Checkout Dependencies') {
            steps {
                script {
                    dir('libs/auth') {
                        git branch: 'main', url: 'https://github.com/tpenha05/store-auth.git'
                        sh 'mvn clean install -DskipTests'
                    }
                    
                    dir('libs/account') {
                        git branch: 'main', url: 'https://github.com/tpenha05/store-account.git'
                        sh 'mvn clean install -DskipTests'
                    }
                }
            }
        }
        
        stage('Build') { 
            steps {
                sh 'mvn -B -DskipTests clean package'
            }
        }      
        
        stage('Build & Push Docker Image') {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: env.REGISTRY_CREDENTIALS, 
                                                   usernameVariable: 'USERNAME', 
                                                   passwordVariable: 'TOKEN')]) {
                        sh """
                            docker login -u \$USERNAME -p \$TOKEN
                            docker build -t ${env.NAME}:latest .
                            docker build -t ${env.NAME}:${env.BUILD_NUMBER} .
                            docker push ${env.NAME}:latest
                            docker push ${env.NAME}:${env.BUILD_NUMBER}
                        """
                    }
                }
            }
        }
    }
}