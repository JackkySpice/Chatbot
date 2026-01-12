.class public Landroidx/appcompat/view/menu/ti$c;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ti$f;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ti;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation


# instance fields
.field public a:Ljava/util/concurrent/ExecutorService;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Landroidx/appcompat/view/menu/tt;->e()Landroidx/appcompat/view/menu/tt;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/tt;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/ti$c;->a:Ljava/util/concurrent/ExecutorService;

    return-void
.end method
