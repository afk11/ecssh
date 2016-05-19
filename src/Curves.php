<?php

namespace Afk11\EcSSH;

use Mdanter\Ecc\Curves\CurveFactory;

class Curves
{
    /**
     * @return array
     */
    public static function listAll()
    {
        return ['nistp256', 'nistp384', 'nistp521'];
    }

    /**
     * @param string $curveName
     * @return \Mdanter\Ecc\Curves\NamedCurveFp|\Mdanter\Ecc\Primitives\CurveFp|\Mdanter\Ecc\Primitives\CurveFpInterface
     */
    public static function curve($curveName)
    {
        switch ($curveName) {
            case 'nistp256':
                return CurveFactory::getCurveByName('nist-p256');
            case 'nistp384':
                return CurveFactory::getCurveByName('nist-p384');
            case 'nistp521':
                return CurveFactory::getCurveByName('nist-p521');
            default:
                throw new \InvalidArgumentException('Unknown or unsupported curve');
        }
    }

    /**
     * @param string $curveName
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    public static function generator($curveName)
    {
        switch ($curveName) {
            case 'nistp256':
                return CurveFactory::getGeneratorByName('nist-p256');
            case 'nistp384':
                return CurveFactory::getGeneratorByName('nist-p384');
            case 'nistp521':
                return CurveFactory::getGeneratorByName('nist-p521');
            default:
                throw new \InvalidArgumentException('Unknown or unsupported generator');
        }
    }

    /**
     * @param string $curveName
     * @return array
     */
    public static function load($curveName)
    {
        return [self::curve($curveName), self::generator($curveName)];
    }
}