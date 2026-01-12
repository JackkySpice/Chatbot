.class public abstract Landroidx/appcompat/view/menu/n41;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static a:Landroidx/appcompat/view/menu/n41;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/n41;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/n41;->a:Landroidx/appcompat/view/menu/n41;

    if-nez v0, :cond_0

    new-instance v0, Landroidx/appcompat/view/menu/o41;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/o41;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/n41;->a:Landroidx/appcompat/view/menu/n41;

    :cond_0
    sget-object v0, Landroidx/appcompat/view/menu/n41;->a:Landroidx/appcompat/view/menu/n41;

    return-object v0
.end method
