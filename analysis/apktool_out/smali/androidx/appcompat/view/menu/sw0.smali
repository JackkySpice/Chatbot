.class public abstract Landroidx/appcompat/view/menu/sw0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/iy0;

.field public static final b:Landroidx/appcompat/view/menu/iy0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/iy0;

    const-string v1, "NONE"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/iy0;-><init>(Ljava/lang/String;)V

    sput-object v0, Landroidx/appcompat/view/menu/sw0;->a:Landroidx/appcompat/view/menu/iy0;

    new-instance v0, Landroidx/appcompat/view/menu/iy0;

    const-string v1, "PENDING"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/iy0;-><init>(Ljava/lang/String;)V

    sput-object v0, Landroidx/appcompat/view/menu/sw0;->b:Landroidx/appcompat/view/menu/iy0;

    return-void
.end method

.method public static final a(Ljava/lang/Object;)Landroidx/appcompat/view/menu/he0;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/rw0;

    if-nez p0, :cond_0

    sget-object p0, Landroidx/appcompat/view/menu/kf0;->a:Landroidx/appcompat/view/menu/iy0;

    :cond_0
    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/rw0;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method

.method public static final synthetic b()Landroidx/appcompat/view/menu/iy0;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/sw0;->a:Landroidx/appcompat/view/menu/iy0;

    return-object v0
.end method

.method public static final synthetic c()Landroidx/appcompat/view/menu/iy0;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/sw0;->b:Landroidx/appcompat/view/menu/iy0;

    return-object v0
.end method

.method public static final d(Landroidx/appcompat/view/menu/qw0;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)Landroidx/appcompat/view/menu/ws;
    .locals 1

    if-ltz p2, :cond_0

    const/4 v0, 0x2

    if-ge p2, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, -0x2

    if-ne p2, v0, :cond_1

    :goto_0
    sget-object v0, Landroidx/appcompat/view/menu/t8;->n:Landroidx/appcompat/view/menu/t8;

    if-ne p3, v0, :cond_1

    return-object p0

    :cond_1
    invoke-static {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/ut0;->a(Landroidx/appcompat/view/menu/tt0;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)Landroidx/appcompat/view/menu/ws;

    move-result-object p0

    return-object p0
.end method
