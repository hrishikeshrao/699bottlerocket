'use strict';

var app = angular.module('AorB',[]);

app.controller('feed', ['$scope', '$rootScope', 'pollsService', function($scope, $rootScope, pollsService) {

  $scope.update = () => {
    pollsService.getPolls().then((response) => {
      $scope.feed = response.data;
      console.log(response.data);
    });
  };

  $rootScope.$on('updateFeed', () => {
    $scope.update();
  });

  $scope.update();

}]);

app.controller('newPoll', ['$scope', '$rootScope', 'pollsService', function($scope, $rootScope, pollsService) {

  $scope.createPoll = (form) => {
    if (form.$valid) {
      pollsService.createPoll($scope.newPoll).then((response) => {
        $scope.resetForm(form);
        $scope.dismissModal();
        $rootScope.$emit('updateFeed', {});
      });
    }
  }

  $scope.resetForm = (form) => {
    $scope.newPoll = {};
    form.$setPristine();
    form.$setUntouched();
  }

  $scope.dismissModal = () => {
        var modalInstance = angular.element(document.querySelector('#modal-create-poll'));
        modalInstance.modal('toggle');
  }

}]);


app.factory('pollsService', ['$http', function($http){

  function getPolls() {
    return $http.get('/showpoll_ng/')
    .then((response) => response);
  }

  function createPoll(data) {
    return $http.post('/create_poll_ng/', data)
    .then((response) => response);
  }

  return {
    getPolls: getPolls,
    createPoll: createPoll
  };
}]);
