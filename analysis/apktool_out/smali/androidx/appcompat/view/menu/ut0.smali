.class public abstract Landroidx/appcompat/view/menu/ut0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/iy0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/iy0;

    const-string v1, "NO_VALUE"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/iy0;-><init>(Ljava/lang/String;)V

    sput-object v0, Landroidx/appcompat/view/menu/ut0;->a:Landroidx/appcompat/view/menu/iy0;

    return-void
.end method

.method public static final a(Landroidx/appcompat/view/menu/tt0;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)Landroidx/appcompat/view/menu/ws;
    .locals 1

    if-eqz p2, :cond_0

    const/4 v0, -0x3

    if-ne p2, v0, :cond_1

    :cond_0
    sget-object v0, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    if-ne p3, v0, :cond_1

    return-object p0

    :cond_1
    new-instance v0, Landroidx/appcompat/view/menu/xa;

    invoke-direct {v0, p0, p1, p2, p3}, Landroidx/appcompat/view/menu/xa;-><init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V

    return-object v0
.end method
