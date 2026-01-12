.class public abstract Landroidx/appcompat/view/menu/cz0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Ljava/util/concurrent/Executor;

.field public static final b:Ljava/util/concurrent/Executor;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/ze2;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/ze2;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/cz0;->a:Ljava/util/concurrent/Executor;

    new-instance v0, Landroidx/appcompat/view/menu/te2;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/te2;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/cz0;->b:Ljava/util/concurrent/Executor;

    return-void
.end method
