<?php

namespace Afk11\EcSSH;

use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\NistCurve;

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
            case NistCurve::NAME_P256:
            case NistCurve::NAME_P384:
            case NistCurve::NAME_P521:
                return CurveFactory::getCurveByName($curveName);
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
            case NistCurve::NAME_P256:
            case NistCurve::NAME_P384:
            case NistCurve::NAME_P521:
                return CurveFactory::getGeneratorByName($curveName);
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
