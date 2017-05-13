#!/usr/bin/env groovy

import groovy.json.JsonSlurperClassic

@Library('sec_ci_libs') _

def master_branches = ["master", ] as String[]

if (master_branches.contains(env.BRANCH_NAME)) {
    // Rebuild main branch once a day
    properties([
        pipelineTriggers([cron('H H * * *')])
    ])
}

// http://stackoverflow.com/a/38439681
@NonCPS
def jsonParse(def json) {
    new groovy.json.JsonSlurperClassic().parseText(json)
}

task_wrapper('mesos-sec', master_branches) {
    stage('Cleanup workspace') {
        deleteDir()
    }

    stage('Checkout') {
        def repo_url
        def repo_sha

        dir("dcos-ee") {
            checkout scm

            // Gather some info about upstream repository
            def upstream_config =  jsonParse(readFile("packages/upstream.json"))
            repo_url = upstream_config['git']
            repo_branch = upstream_config['ref_origin']
        }

        dir("dcos-open") {
            git branch: repo_branch, credentialsId: 'a7ac7f84-64ea-4483-8e66-bb204484e58f', poll: false, url: repo_url
            sh 'echo `pwd` > ../dcos-ee/packages/adminrouter/extra/src/.dcos-open.path'
        }
    }

    dir("dcos-ee/packages/adminrouter/extra/src/") {
        stage('Apply EE overlay on top of Open') {
            sh 'make apply-open'
        }

        stage('Prepare devkit container') {
            sh 'make update-devkit'
        }

        try {
            stage('make api-docs') {
                sh 'make api-docs'
            }

            stage('make flake8') {
                sh 'make flake8'
            }

            stage('make test') {
                sh 'make test'
            }

        } finally {

            stage('archive build artifacts') {
                archiveArtifacts artifacts: 'test-harness/logs/*.log', allowEmptyArchive: true, excludes: 'test_harness/', fingerprint: true
            }

            stage('Cleanup docker container'){
                sh 'make clean-containers'
                sh "docker rmi -f adminrouter-devkit || true"
            }
        }
    }
}
